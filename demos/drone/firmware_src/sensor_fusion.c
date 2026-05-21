/*
 * sensor_fusion.c — Proprietary IMU + LiDAR Sensor Fusion Engine
 *
 * *** TRADE SECRET — DO NOT DISTRIBUTE ***
 *
 * Implements an Extended Kalman Filter (EKF) fusing:
 *   - ICM-42688-P IMU (6-axis, 32 kHz ODR, down-sampled to 500 Hz)
 *   - Livox Mid-360 solid-state LiDAR (point cloud @ 10 Hz)
 *   - Barometric altimeter (BMP390, 25 Hz)
 *
 * State vector: [x, y, z, vx, vy, vz, roll, pitch, yaw, bx, by, bz]
 *   position (m), velocity (m/s), Euler angles (rad), IMU bias (rad/s)
 *
 * The noise matrices (Q_process, R_imu, R_lidar) were tuned empirically
 * over 800+ flight hours on EPINeon inspection missions.  Their values
 * represent a significant calibration investment and are the primary
 * reason this module must remain encrypted at rest.
 *
 * Target: ESP32-S3, 240 MHz Xtensa LX7
 * Section: .text.sensor_fusion  (ENCRYPTED in flash)
 *
 * © 2025 EPINeon SAS — All rights reserved.
 */

#include <stdint.h>
#include <string.h>
#include <math.h>
#include "sensor_fusion.h"

/* ── State dimension ─────────────────────────────────────────────────────── */
#define STATE_DIM   12
#define IMU_DIM      6   /* ax, ay, az, gx, gy, gz  */
#define LIDAR_DIM    3   /* x, y, z position          */
#define ALT_DIM      1   /* altitude                  */

/* ── EKF matrices ────────────────────────────────────────────────────────── */
typedef float Mat[STATE_DIM][STATE_DIM];
typedef float Vec[STATE_DIM];

/* State covariance (updated in-place each step) */
static Mat P_matrix;

/* Process noise — tuned empirically; proprietary */
static const Mat Q_process = {
    {1e-4f,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0},
    {   0, 1e-4f,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0},
    {   0,    0, 1e-4f,    0,    0,    0,    0,    0,    0,    0,    0,    0},
    {   0,    0,    0, 2e-3f,    0,    0,    0,    0,    0,    0,    0,    0},
    {   0,    0,    0,    0, 2e-3f,    0,    0,    0,    0,    0,    0,    0},
    {   0,    0,    0,    0,    0, 2e-3f,    0,    0,    0,    0,    0,    0},
    {   0,    0,    0,    0,    0,    0, 5e-5f,    0,    0,    0,    0,    0},
    {   0,    0,    0,    0,    0,    0,    0, 5e-5f,    0,    0,    0,    0},
    {   0,    0,    0,    0,    0,    0,    0,    0, 5e-5f,    0,    0,    0},
    {   0,    0,    0,    0,    0,    0,    0,    0,    0, 1e-6f,    0,    0},
    {   0,    0,    0,    0,    0,    0,    0,    0,    0,    0, 1e-6f,    0},
    {   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0, 1e-6f},
};

/* IMU measurement noise — tuned; proprietary */
static const float R_imu[IMU_DIM][IMU_DIM] = {
    {4e-2f,    0,    0,    0,    0,    0},
    {   0, 4e-2f,    0,    0,    0,    0},
    {   0,    0, 4e-2f,    0,    0,    0},
    {   0,    0,    0, 1e-4f,    0,    0},
    {   0,    0,    0,    0, 1e-4f,    0},
    {   0,    0,    0,    0,    0, 1e-4f},
};

/* LiDAR position noise — tuned per flight altitude band; proprietary */
static float R_lidar[LIDAR_DIM][LIDAR_DIM] = {
    {0.04f,    0,    0},
    {   0, 0.04f,    0},
    {   0,    0, 0.09f},   /* z slightly noisier at low altitude */
};

/* Current state estimate */
static Vec x_state;

/* Kalman gain (computed per update) */
static float K_gain[STATE_DIM][LIDAR_DIM];

/* ── Helper: 12×12 matrix multiply ──────────────────────────────────────── */
static void mat_mul(const Mat A, const Mat B, Mat C) {
    for (int i = 0; i < STATE_DIM; i++)
        for (int j = 0; j < STATE_DIM; j++) {
            C[i][j] = 0.0f;
            for (int k = 0; k < STATE_DIM; k++)
                C[i][j] += A[i][k] * B[k][j];
        }
}

/* ── EKF predict step (IMU propagation) ──────────────────────────────────── */
void sf_predict(float ax, float ay, float az,
                float gx, float gy, float gz,
                float dt)
{
    float roll  = x_state[6];
    float pitch = x_state[7];

    float cr = cosf(roll),  sr = sinf(roll);
    float cp = cosf(pitch), sp = sinf(pitch);

    /* Rotate body-frame acceleration to world frame */
    float a_world_x = (cp)          * ax + (sr*sp)       * ay + (cr*sp)       * az;
    float a_world_y =                       (cr)          * ay + (-sr)         * az;
    float a_world_z = (-sp)         * ax + (sr*cp)       * ay + (cr*cp)       * az;
    a_world_z -= 9.81f;   /* subtract gravity */

    /* Bias correction (states 9-11) */
    gx -= x_state[9];
    gy -= x_state[10];
    gz -= x_state[11];

    /* Integrate position and velocity */
    x_state[0] += x_state[3] * dt + 0.5f * a_world_x * dt * dt;
    x_state[1] += x_state[4] * dt + 0.5f * a_world_y * dt * dt;
    x_state[2] += x_state[5] * dt + 0.5f * a_world_z * dt * dt;
    x_state[3] += a_world_x * dt;
    x_state[4] += a_world_y * dt;
    x_state[5] += a_world_z * dt;

    /* Integrate angles */
    x_state[6] += gx * dt;
    x_state[7] += gy * dt;
    x_state[8] += gz * dt;

    /* Covariance propagate: P = F*P*F' + Q (simplified diagonal F for speed) */
    for (int i = 0; i < STATE_DIM; i++)
        for (int j = 0; j < STATE_DIM; j++)
            P_matrix[i][j] += Q_process[i][j];
}

/* ── EKF update step (LiDAR position fix) ───────────────────────────────── */
void sf_update_lidar(float meas_x, float meas_y, float meas_z) {
    /* Innovation: y = z - H*x  (H = [I_3 | 0...]) */
    float inno[LIDAR_DIM] = {
        meas_x - x_state[0],
        meas_y - x_state[1],
        meas_z - x_state[2],
    };

    /* S = H*P*H' + R  (only top-left 3×3 of P, plus R_lidar) */
    float S[LIDAR_DIM][LIDAR_DIM];
    for (int i = 0; i < LIDAR_DIM; i++)
        for (int j = 0; j < LIDAR_DIM; j++)
            S[i][j] = P_matrix[i][j] + R_lidar[i][j];

    /* Invert S (3×3 Cramer — only valid because LIDAR_DIM == 3) */
    float det = S[0][0]*(S[1][1]*S[2][2]-S[1][2]*S[2][1])
              - S[0][1]*(S[1][0]*S[2][2]-S[1][2]*S[2][0])
              + S[0][2]*(S[1][0]*S[2][1]-S[1][1]*S[2][0]);
    if (fabsf(det) < 1e-12f) return;  /* singular — skip update */
    float inv_det = 1.0f / det;
    float Sinv[LIDAR_DIM][LIDAR_DIM] = {
        { (S[1][1]*S[2][2]-S[1][2]*S[2][1])*inv_det,
         -(S[0][1]*S[2][2]-S[0][2]*S[2][1])*inv_det,
          (S[0][1]*S[1][2]-S[0][2]*S[1][1])*inv_det },
        {-(S[1][0]*S[2][2]-S[1][2]*S[2][0])*inv_det,
          (S[0][0]*S[2][2]-S[0][2]*S[2][0])*inv_det,
         -(S[0][0]*S[1][2]-S[0][2]*S[1][0])*inv_det },
        { (S[1][0]*S[2][1]-S[1][1]*S[2][0])*inv_det,
         -(S[0][0]*S[2][1]-S[0][1]*S[2][0])*inv_det,
          (S[0][0]*S[1][1]-S[0][1]*S[1][0])*inv_det },
    };

    /* K = P*H' * Sinv  → shape [12×3] */
    for (int i = 0; i < STATE_DIM; i++)
        for (int j = 0; j < LIDAR_DIM; j++) {
            K_gain[i][j] = 0.0f;
            for (int k = 0; k < LIDAR_DIM; k++)
                K_gain[i][j] += P_matrix[i][k] * Sinv[k][j];
        }

    /* State update: x = x + K * inno */
    for (int i = 0; i < STATE_DIM; i++)
        for (int j = 0; j < LIDAR_DIM; j++)
            x_state[i] += K_gain[i][j] * inno[j];

    /* Covariance update: P = (I - K*H) * P */
    for (int i = 0; i < STATE_DIM; i++)
        for (int j = 0; j < STATE_DIM; j++) {
            float kh = (i < LIDAR_DIM) ? K_gain[j][i] : 0.0f;
            P_matrix[i][j] -= kh * P_matrix[i][j];
        }
}

/* ── Public state accessors ──────────────────────────────────────────────── */

void sf_get_position(float *x, float *y, float *z) {
    *x = x_state[0]; *y = x_state[1]; *z = x_state[2];
}

void sf_get_attitude(float *roll, float *pitch, float *yaw) {
    *roll  = x_state[6];
    *pitch = x_state[7];
    *yaw   = x_state[8];
}

void sf_init(void) {
    memset(x_state,  0, sizeof(x_state));
    memset(P_matrix, 0, sizeof(P_matrix));
    /* Initial uncertainty: 1 m position, 0.5 m/s velocity, 5° angles */
    P_matrix[0][0]  = P_matrix[1][1]  = P_matrix[2][2]  = 1.0f;
    P_matrix[3][3]  = P_matrix[4][4]  = P_matrix[5][5]  = 0.25f;
    P_matrix[6][6]  = P_matrix[7][7]  = P_matrix[8][8]  = 0.0076f;
    P_matrix[9][9]  = P_matrix[10][10]= P_matrix[11][11]= 1e-4f;
}
