/*
 * Filename: roblox_offsets.h
 *
 * Copyright (c) 2026 compiledkernel-idk
 * All Rights Reserved.
 *
 * This software is proprietary and confidential.
 * Unauthorized copying, distribution, or use of this file,
 * via any medium, is strictly prohibited.
 */

#ifndef ROBLOX_OFFSETS_H
#define ROBLOX_OFFSETS_H

#include <stdint.h>

// Sober Specific Anchors (Relative to sober binary base)
#define OFF_GLOBALSTATE_ANCHOR 0x586520
#define OFF_LUA_STATE_ANCHOR 0x6fce08

#define OFF_VISUALENGINE_FAKE_TO_REAL_DATAMODEL 0x1C0
#define OFF_VISUALENGINE_POINTER 0x7AE30D0
#define OFF_VISUALENGINE_RENDERVIEW 0x800
#define OFF_VISUALENGINE_TO_FAKE_DATAMODEL 0x700
#define OFF_VISUALENGINE_VIEWMATRIX 0x180
#define OFF_VISUALENGINE_WINDOW_DIMENSIONS 0x720

#define OFF_RENDERVIEW_INVALIDATE_LIGHTING 0x148

#define OFF_DATAMODEL_CLIENT_REPLICATOR 0x3E8
#define OFF_DATAMODEL_CREATOR_ID 0x188
#define OFF_DATAMODEL_GAME_ID 0x190
#define OFF_DATAMODEL_GAME_LOADED 0x608
#define OFF_DATAMODEL_JOB_ID 0x138
#define OFF_DATAMODEL_PLACE_ID 0x198
#define OFF_DATAMODEL_RUN_SERVICE 0x3A0
#define OFF_DATAMODEL_SERVER_IP 0x5F0
#define OFF_DATAMODEL_USER_INPUT_SERVICE 0x3B0
#define OFF_DATAMODEL_WORKSPACE 0x178

#define OFF_INSTANCE_ATTRIBUTE_CONTAINER 0x48
#define OFF_INSTANCE_ATTRIBUTE_LIST 0x18
#define OFF_INSTANCE_ATTRIBUTE_TO_NEXT 0x58
#define OFF_INSTANCE_ATTRIBUTE_TO_VALUE 0x18
#define OFF_INSTANCE_CHILDREN_END 0x8
#define OFF_INSTANCE_CHILDREN_START 0x70
#define OFF_INSTANCE_CLASS_DESCRIPTOR 0x18
#define OFF_INSTANCE_CLASS_NAME 0x8
#define OFF_INSTANCE_NAME 0xB0
#define OFF_INSTANCE_PARENT 0x68

#define OFF_WORKSPACE_CAMERA 0x458
#define OFF_WORKSPACE_GRAVITY 0x9B0

#define OFF_PLAYERS_LOCAL_PLAYER 0x130

#define OFF_PLAYER_CHARACTER 0x360
#define OFF_PLAYER_DISPLAY_NAME 0x130
#define OFF_PLAYER_TEAM 0x270
#define OFF_PLAYER_USER_ID 0x298

#define OFF_HUMANOID_HEALTH 0x194
#define OFF_HUMANOID_MAX_HEALTH 0x1B4
#define OFF_HUMANOID_WALK_SPEED 0x1D4
#define OFF_HUMANOID_JUMP_POWER 0x1B0

#define OFF_PART_POSITION 0xE4
#define OFF_PART_ROTATION 0xC0
#define OFF_PART_SIZE 0x1B0
#define OFF_PART_COLOR3 0x194
#define OFF_PART_TRANSPARENCY 0xF0
#define OFF_PART_PRIMITIVE 0x148

#define OFF_BYTECODE_POINTER 0x10
#define OFF_BYTECODE_SIZE 0x20

#define OFF_MODULESCRIPT_BYTECODE 0x150
#define OFF_MODULESCRIPT_HASH 0x160

#define OFF_LOCALSCRIPT_BYTECODE 0x1A8
#define OFF_LOCALSCRIPT_HASH 0x1B8

#define OFF_CAMERA_FOV 0x160
#define OFF_CAMERA_POSITION 0x11C
#define OFF_CAMERA_ROTATION 0xF8

typedef struct {
  uintptr_t base;
  uintptr_t datamodel;
  uintptr_t workspace;
  uintptr_t players;
  uintptr_t local_player;
  uintptr_t camera;
} roblox_state_t;

int find_datamodel(uintptr_t sober_base, roblox_state_t *state);
int find_local_player(roblox_state_t *state);
uintptr_t get_instance_child(uintptr_t instance, const char *name);
const char *get_instance_name(uintptr_t instance);
const char *get_instance_class(uintptr_t instance);

#endif
