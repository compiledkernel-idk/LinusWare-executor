
#define _GNU_SOURCE
#include "roblox_offsets.h"
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void log_debug(const char *fmt, ...);

static sigjmp_buf g_jmp;
static volatile int g_safe = 0;

static void sig_handler(int sig) {
  (void)sig;
  if (g_safe) {
    g_safe = 0;
    siglongjmp(g_jmp, 1);
  }
}

static uintptr_t safe_read_ptr(uintptr_t addr) {
  struct sigaction sa, old;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sig_handler;
  sigaction(SIGSEGV, &sa, &old);

  uintptr_t result = 0;
  g_safe = 1;

  if (sigsetjmp(g_jmp, 1) == 0) {
    result = *(uintptr_t *)addr;
    g_safe = 0;
  }

  sigaction(SIGSEGV, &old, NULL);
  return result;
}

static int safe_read_int(uintptr_t addr) {
  struct sigaction sa, old;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sig_handler;
  sigaction(SIGSEGV, &sa, &old);

  int result = 0;
  g_safe = 1;

  if (sigsetjmp(g_jmp, 1) == 0) {
    result = *(int *)addr;
    g_safe = 0;
  }

  sigaction(SIGSEGV, &old, NULL);
  return result;
}

static const char *safe_read_string(uintptr_t addr) {
  struct sigaction sa, old;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sig_handler;
  sigaction(SIGSEGV, &sa, &old);

  const char *result = NULL;
  g_safe = 1;

  if (sigsetjmp(g_jmp, 1) == 0) {
    uintptr_t str_ptr = *(uintptr_t *)addr;
    if (str_ptr > 0x10000) {
      result = (const char *)str_ptr;
    }
    g_safe = 0;
  }

  sigaction(SIGSEGV, &old, NULL);
  return result;
}

static int validate_datamodel_chain(uintptr_t ve_ptr) {
  if (!ve_ptr || ve_ptr < 0x10000)
    return 0;

  uintptr_t fake_dm =
      safe_read_ptr(ve_ptr + OFF_VISUALENGINE_TO_FAKE_DATAMODEL);
  if (!fake_dm || fake_dm < 0x10000)
    return 0;

  uintptr_t real_dm =
      safe_read_ptr(fake_dm + OFF_VISUALENGINE_FAKE_TO_REAL_DATAMODEL);
  if (!real_dm || real_dm < 0x10000)
    return 0;

  uintptr_t workspace = safe_read_ptr(real_dm + OFF_DATAMODEL_WORKSPACE);
  if (!workspace)
    return 1;

  return 2;
}

uintptr_t scan_for_visualengine(uintptr_t sober_base) {
  log_debug("Scanning for VisualEngine...\n");

  static const uintptr_t SCAN_OFFSETS[] = {
      0x7AE30D0, 0x7AE0000, 0x7B00000, 0x7C00000, 0x6000000, 0x6500000,
      0x7000000, 0x7500000, 0x5000000, 0x5500000, 0x4000000, 0x4500000,
      0x3000000, 0x3500000, 0x2000000, 0x2500000, 0x1000000, 0x1500000,
      0x0800000, 0x0C00000, 0x0500000, 0x0600000, 0x0700000, 0};

  uintptr_t best_offset = 0;
  int best_score = 0;

  for (int i = 0; SCAN_OFFSETS[i] != 0; i++) {
    uintptr_t off = SCAN_OFFSETS[i];
    uintptr_t ve_ptr = safe_read_ptr(sober_base + off);

    if (ve_ptr && ve_ptr > 0x10000) {
      int score = validate_datamodel_chain(ve_ptr);
      if (score > best_score) {
        best_score = score;
        best_offset = off;
        log_debug("  Offset 0x%lx: score=%d\n", off, score);
        if (score >= 2)
          return best_offset;
      }
    }
  }

  log_debug("Scan done. Best: 0x%lx (score=%d)\n", best_offset, best_score);
  return best_offset;
}

int find_datamodel(uintptr_t sober_base, roblox_state_t *state) {
  if (!sober_base || !state)
    return -1;

  log_debug("=== FINDING DATAMODEL ===\n");
  log_debug("Sober base: 0x%lx\n", sober_base);

  state->base = sober_base;

  uintptr_t ve_offset = scan_for_visualengine(sober_base);
  if (!ve_offset) {
    ve_offset = OFF_VISUALENGINE_POINTER;
    log_debug("Falling back to Windows offset: 0x%lx\n", ve_offset);
  }

  uintptr_t visual_engine = sober_base + ve_offset;
  log_debug("VisualEngine pointer at: 0x%lx (offset 0x%lx)\n", visual_engine,
            ve_offset);

  uintptr_t ve_ptr = safe_read_ptr(visual_engine);
  if (!ve_ptr) {
    log_debug("Failed to read VisualEngine pointer\n");
    return -1;
  }
  log_debug("VisualEngine: 0x%lx\n", ve_ptr);

  uintptr_t fake_dm =
      safe_read_ptr(ve_ptr + OFF_VISUALENGINE_TO_FAKE_DATAMODEL);
  if (!fake_dm) {
    log_debug("Failed to read FakeDataModel\n");
    return -1;
  }
  log_debug("FakeDataModel: 0x%lx\n", fake_dm);

  uintptr_t real_dm =
      safe_read_ptr(fake_dm + OFF_VISUALENGINE_FAKE_TO_REAL_DATAMODEL);
  if (!real_dm) {
    log_debug("Failed to read RealDataModel\n");
    return -1;
  }
  log_debug("RealDataModel: 0x%lx\n", real_dm);

  state->datamodel = real_dm;

  state->workspace = safe_read_ptr(real_dm + OFF_DATAMODEL_WORKSPACE);
  log_debug("Workspace: 0x%lx\n", state->workspace);

  return 0;
}

int find_local_player(roblox_state_t *state) {
  if (!state || !state->datamodel)
    return -1;

  log_debug("=== FINDING LOCAL PLAYER ===\n");

  uintptr_t dm = state->datamodel;
  uintptr_t children_start = safe_read_ptr(dm + OFF_INSTANCE_CHILDREN_START);
  uintptr_t children_end = safe_read_ptr(dm + OFF_INSTANCE_CHILDREN_START +
                                         OFF_INSTANCE_CHILDREN_END);

  log_debug("DataModel children: 0x%lx - 0x%lx\n", children_start,
            children_end);

  if (!children_start || !children_end)
    return -1;

  for (uintptr_t ptr = children_start; ptr < children_end;
       ptr += sizeof(uintptr_t)) {
    uintptr_t child = safe_read_ptr(ptr);
    if (!child)
      continue;

    const char *name = get_instance_name(child);
    if (name && strcmp(name, "Players") == 0) {
      state->players = child;
      log_debug("Found Players: 0x%lx\n", child);

      state->local_player = safe_read_ptr(child + OFF_PLAYERS_LOCAL_PLAYER);
      log_debug("LocalPlayer: 0x%lx\n", state->local_player);

      if (state->local_player) {
        const char *player_name = get_instance_name(state->local_player);
        log_debug("LocalPlayer name: %s\n",
                  player_name ? player_name : "(null)");
      }

      break;
    }
  }

  if (state->workspace) {
    state->camera = safe_read_ptr(state->workspace + OFF_WORKSPACE_CAMERA);
    log_debug("Camera: 0x%lx\n", state->camera);
  }

  return state->local_player ? 0 : -1;
}

const char *get_instance_name(uintptr_t instance) {
  if (!instance)
    return NULL;
  return safe_read_string(instance + OFF_INSTANCE_NAME);
}

const char *get_instance_class(uintptr_t instance) {
  if (!instance)
    return NULL;

  uintptr_t class_desc =
      safe_read_ptr(instance + OFF_INSTANCE_CLASS_DESCRIPTOR);
  if (!class_desc)
    return NULL;

  return safe_read_string(class_desc + OFF_INSTANCE_CLASS_NAME);
}

uintptr_t get_instance_child(uintptr_t instance, const char *name) {
  if (!instance || !name)
    return 0;

  uintptr_t children_start =
      safe_read_ptr(instance + OFF_INSTANCE_CHILDREN_START);
  uintptr_t children_end = safe_read_ptr(
      instance + OFF_INSTANCE_CHILDREN_START + OFF_INSTANCE_CHILDREN_END);

  if (!children_start || !children_end)
    return 0;

  for (uintptr_t ptr = children_start; ptr < children_end;
       ptr += sizeof(uintptr_t)) {
    uintptr_t child = safe_read_ptr(ptr);
    if (!child)
      continue;

    const char *child_name = get_instance_name(child);
    if (child_name && strcmp(child_name, name) == 0) {
      return child;
    }
  }

  return 0;
}

void dump_roblox_state(roblox_state_t *state) {
  if (!state)
    return;

  log_debug("\n=== ROBLOX STATE DUMP ===\n");
  log_debug("Base:        0x%lx\n", state->base);
  log_debug("DataModel:   0x%lx\n", state->datamodel);
  log_debug("Workspace:   0x%lx\n", state->workspace);
  log_debug("Players:     0x%lx\n", state->players);
  log_debug("LocalPlayer: 0x%lx\n", state->local_player);
  log_debug("Camera:      0x%lx\n", state->camera);

  if (state->local_player) {
    const char *name = get_instance_name(state->local_player);
    int userid = safe_read_int(state->local_player + OFF_PLAYER_USER_ID);
    log_debug("\nPlayer Info:\n");
    log_debug("  Name: %s\n", name ? name : "(null)");
    log_debug("  UserId: %d\n", userid);

    uintptr_t character =
        safe_read_ptr(state->local_player + OFF_PLAYER_CHARACTER);
    log_debug("  Character: 0x%lx\n", character);
  }

  if (state->camera) {
    float fov = 0;
    struct sigaction sa, old;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGSEGV, &sa, &old);
    g_safe = 1;
    if (sigsetjmp(g_jmp, 1) == 0) {
      fov = *(float *)(state->camera + OFF_CAMERA_FOV);
      g_safe = 0;
    }
    sigaction(SIGSEGV, &old, NULL);

    log_debug("\nCamera Info:\n");
    log_debug("  FOV: %.1f\n", fov);
  }

  log_debug("=========================\n");
}
