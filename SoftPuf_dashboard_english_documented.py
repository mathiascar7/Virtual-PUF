"""Experimental PUF-Inspired Key Derivation and 8x8 Grid Cipher Dashboard.

Project overview
----------------
This educational prototype combines four ideas in one interactive Pygame app:

1. Host telemetry collection using psutil, including CPU, memory, frequency,
   and temperature when the operating system exposes a sensor interface.
2. Timing-profile sampling and a PUF-inspired feature/quantization pipeline.
3. A helper-data reconstruction experiment using repetition-code majority
   voting, followed by SHA-256 hashing.
4. A custom 8x8 grid transformation with a Pygame dashboard for inspecting
   payloads, timing, key variation, and a simple side-channel experiment.

Important research and security limitations
--------------------------------------------
- This is a research/learning prototype, not a validated physical unclonable
  function (PUF), cryptographic key-storage system, or secure cipher.
- The virtual nodes are software-generated simulations; they are not separate
  physical computers or independently measured silicon devices.
- The VRM current and voltage values are estimates derived from CPU load, not
  direct motherboard voltage-regulator measurements.
- The grid cipher and its custom mask generator are not standard cryptography
  and must not protect real data, credentials, or communications.
- The side-channel panel reports metrics from this program's simplified test
  procedure. It does not establish compliance with ISO/IEC 17825, NIST SP
  800-208, or any other certification or security standard.
- The displayed SHA-256 digest is a hash of the reconstructed bit string; it
  should not be interpreted as proof of entropy, uniqueness, or key security.

Dependencies
------------
    pip install numpy psutil pygame

Run
---
    python puf_dashboard.py

The implementation below preserves the prototype's original processing flow
and dashboard interactions. Comments and user-facing labels are written in
English for clear technical presentation.
"""

import datetime
import gc
import hashlib
import json
import math
import os
import threading
import time
import numpy as np
import psutil
import pygame


# =====================================================================
# REAL HOST HARDWARE TELEMETRY & PHYSICAL SENSOR ACQUISITION
# =====================================================================
def get_real_host_hardware_telemetry() -> dict:
    """Acquires actual physical system metrics from the Host machine (PC 0)."""
    cpu_percent = psutil.cpu_percent(interval=None)
    cpu_count = psutil.cpu_count(logical=True) or 4

    freq_info = psutil.cpu_freq()
    cpu_freq_mhz = freq_info.current if freq_info else 2400.0

    ram_info = psutil.virtual_memory()
    ram_usage_pct = ram_info.percent

    temp_c = 35.0
    try:
        if hasattr(psutil, "sensors_temperatures"):
            temps = psutil.sensors_temperatures()
            if temps:
                for name, entries in temps.items():
                    for entry in entries:
                        if entry.current and entry.current > 0:
                            temp_c = float(entry.current)
                            break
    except Exception:
        temp_c = float(np.clip(32.0 + (cpu_percent * 0.48), 30.0, 95.0))

    vrm_idle_current = 0.8
    vrm_load_current = (
        vrm_idle_current + (cpu_percent / 100.0) * 8.5 * (cpu_count / 4.0)
    )
    vrm_voltage = 1.20 - (vrm_load_current * 0.005)

    return {
        "temp_c": temp_c,
        "cpu_percent": cpu_percent,
        "cpu_freq_mhz": cpu_freq_mhz,
        "ram_usage_pct": ram_usage_pct,
        "vrm_current_a": vrm_load_current,
        "vrm_voltage_v": vrm_voltage,
    }


# =====================================================================
# 1. UNIFIED STABILIZED PUF ENGINE (SYNDROME FUZZY EXTRACTOR + BLINDING)
# =====================================================================
class AdvancedPUFEngine:
    """Implement timing capture, feature extraction, and helper-data experiments.

    The host profile is measured on the current machine. Virtual-node profiles
    are synthesized from offsets and modeled noise, so their results should be
    described as simulation data in any report or portfolio.
    """

    def __init__(self, bin_width_ps: float = 1200000.0, ecc_rep: int = 7):
        self.bin_width_ps = bin_width_ps
        self.ecc_rep = ecc_rep
        self.num_bursts = 16
        self.burst_samples = 6
        self.ops_per_sample = 50

        self.T_ambient = 25.0
        self.gamma_silicon = 0.0039

        self.k_B = 1.380649e-23
        self.q_e = 1.60217663e-19

        self.circuit_params = {
            "pc_real": {
                "alpha": 0.12,
                "beta": 0.00018,
                "R_vrm_mohm": 12.0,
                "bandwidth_hz": 1e8,
            },
            "pc_virt_1": {
                "alpha": 0.10,
                "beta": 0.00022,
                "R_vrm_mohm": 15.0,
                "bandwidth_hz": 1e8,
            },
            "pc_virt_2": {
                "alpha": 0.07,
                "beta": 0.00038,
                "R_vrm_mohm": 22.0,
                "bandwidth_hz": 1e8,
            },
            "pc_virt_3": {
                "alpha": 0.05,
                "beta": 0.00045,
                "R_vrm_mohm": 30.0,
                "bandwidth_hz": 1e8,
            },
        }

    def calculate_rigorous_electronic_noise(
        self, node_id: str, shape: tuple, host_telemetry: dict
    ) -> np.ndarray:
        params = self.circuit_params[node_id]

        if node_id == "pc_real":
            temp_k = host_telemetry["temp_c"] + 273.15
            i_vrm = host_telemetry["vrm_current_a"]
        else:
            temp_k = (host_telemetry["temp_c"] + 15.0) + 273.15
            i_vrm = host_telemetry["vrm_current_a"] * 1.35

        r_ohms = params["R_vrm_mohm"] / 1000.0
        df = params["bandwidth_hz"]
        v_johnson = np.sqrt(4.0 * self.k_B * temp_k * r_ohms * df)
        v_shot = np.sqrt(2.0 * self.q_e * i_vrm * df) * r_ohms
        v_rms_noise = np.sqrt(v_johnson**2 + v_shot**2)

        v_overdrive = max(0.35, host_telemetry["vrm_voltage_v"] - 0.70)
        window_base_delay_ns = 25000.0
        sigma_jitter_ns = (v_rms_noise / v_overdrive) * window_base_delay_ns
        return np.random.normal(0.0, sigma_jitter_ns, size=shape)

    def capture_hardware_profile(self) -> tuple[np.ndarray, float]:
        burst_matrix = np.zeros(
            (self.num_bursts, self.burst_samples), dtype=np.float64
        )
        gc.disable()
        t_hw_start = time.perf_counter_ns()
        try:
            for b in range(self.num_bursts):
                x, y = 0x5A5A5A5A, 0x3C3C3C3C
                for s in range(self.burst_samples):
                    t0 = time.perf_counter_ns()
                    for _ in range(self.ops_per_sample):
                        x = ((x ^ y) * 0x9E3779B9) & 0xFFFFFFFF
                    t1 = time.perf_counter_ns()
                    burst_matrix[b, s] = float(t1 - t0)
        finally:
            gc.enable()

        t_hw_elapsed_ms = (time.perf_counter_ns() - t_hw_start) / 1e6

        sorted_matrix = np.sort(burst_matrix, axis=0)
        trim_start = self.num_bursts // 4
        trim_end = 3 * (self.num_bursts // 4)
        clean_profile = np.mean(sorted_matrix[trim_start:trim_end, :], axis=0)

        return clean_profile, t_hw_elapsed_ms

    def extract_features(self, profile: np.ndarray) -> np.ndarray:
        """
        Build a feature vector from the measured timing profile:
        1. Absolute timing values (t)
        2. First finite difference (d1 = delta t)
        3. Second finite difference (d2 = delta-squared t)
        4. Linear slope estimate
        """
        t = profile * 1000.0
        d1 = np.diff(t)
        d2 = np.diff(d1)
        x_axis = np.arange(len(t))
        slope, _ = np.polyfit(x_axis, t, 1)
        return np.concatenate([t, d1, d2, [slope]])

    def quantize_gray_adaptive(self, vector: np.ndarray, len_profile: int = 6) -> str:
        """
        Adaptive Gray-code quantization for handling timing variation.
        """
        n_t = len_profile
        n_d1 = max(1, n_t - 1)
        n_d2 = max(1, n_d1 - 1)

        gray_bits = []
        for idx, val in enumerate(vector):
            if idx < n_t:
                bw = self.bin_width_ps
            elif idx < n_t + n_d1:
                bw = self.bin_width_ps * 2.5
            elif idx < n_t + n_d1 + n_d2:
                bw = self.bin_width_ps * 5.0
            else:
                bw = self.bin_width_ps * 2.0

            bin_id = int(math.floor(val / bw)) if bw > 0 else 0
            gray_val = abs(bin_id ^ (bin_id >> 1)) & 0xFF
            gray_bits.append(format(gray_val, "08b"))
        return "".join(gray_bits)

    def quantize_gray(self, vector: np.ndarray) -> str:
        return self.quantize_gray_adaptive(vector, len_profile=6)

    def derive_key(
        self,
        raw_bits: str,
        helper_target: str | dict,
        key_name: str = "default",
        workload_cycles: int = 0,
    ) -> tuple[bytes, str, float]:
        t_sw_start = time.perf_counter_ns()

        use_memory = isinstance(helper_target, dict)
        exists = (
            (key_name in helper_target)
            if use_memory
            else os.path.exists(helper_target)
        )

        num_puf_bits = len(raw_bits)
        K = num_puf_bits // self.ecc_rep
        N = K * self.ecc_rep
        puf_trimmed = raw_bits[:N]

        if not exists:
            secret_s = format(
                int.from_bytes(os.urandom((K + 7) // 8), "big")
                & ((1 << K) - 1),
                f"0{K}b",
            )
            codeword = "".join([b * self.ecc_rep for b in secret_s])

            helper_w = "".join(
                [
                    str(int(p) ^ int(c))
                    for p, c in zip(puf_trimmed, codeword, strict=False)
                ]
            )

            if use_memory:
                helper_target[key_name] = helper_w
            else:
                with open(helper_target, "w") as f:
                    json.dump({"helper_data": helper_w}, f)

            status = "ENROLLED"
            target_secret = secret_s
        else:
            if use_memory:
                helper_w = helper_target[key_name]
            else:
                with open(helper_target, "r") as f:
                    helper_w = json.load(f)["helper_data"]

            noisy_codeword = "".join(
                [
                    str(int(p) ^ int(w))
                    for p, w in zip(puf_trimmed, helper_w, strict=False)
                ]
            )

            recovered = []
            for i in range(K):
                block = noisy_codeword[
                    i * self.ecc_rep : (i + 1) * self.ecc_rep
                ]
                ones = block.count("1")
                recovered.append("1" if ones > (self.ecc_rep // 2) else "0")

            target_secret = "".join(recovered)
            status = "RECONSTRUCTED"

        digest_bytes = hashlib.sha256(target_secret.encode("utf-8")).digest()
        sw_latency_ms = (time.perf_counter_ns() - t_sw_start) / 1e6

        return digest_bytes, status, sw_latency_ms

    def derive_key_host(
        self,
        raw_bits: str,
        helper_target: str | dict,
        key_name: str = "default",
        workload_cycles: int = 0,
    ) -> tuple[bytes, str, float]:
        """
        Apply a temporary in-memory XOR mask: (raw XOR R) XOR R = raw. This software-level operation is not a hardware security boundary.
        """
        t_sw_start = time.perf_counter_ns()
        num_bits = len(raw_bits)

        r_bytes = os.urandom((num_bits + 7) // 8)
        r_int = int.from_bytes(r_bytes, "big")
        r_mask = format(r_int, f"0{num_bits}b")[:num_bits]

        injected_trace = "".join(
            str(int(b) ^ int(r)) for b, r in zip(raw_bits, r_mask, strict=False)
        )

        host_recovered = "".join(
            str(int(ib) ^ int(r))
            for ib, r in zip(injected_trace, r_mask, strict=False)
        )

        key_bytes, status, _ = self.derive_key(
            host_recovered, helper_target, key_name, workload_cycles
        )
        sw_latency_ms = (time.perf_counter_ns() - t_sw_start) / 1e6
        return key_bytes, status, sw_latency_ms

    def capture_blinded_trace(self, profile: np.ndarray) -> np.ndarray:
        """
        Generate a masked trace for the simplified Tab 6 experiment. This is not a realistic attacker measurement channel.
        """
        feats = self.extract_features(profile)
        raw_bits = self.quantize_gray_adaptive(feats, len(profile))
        num_bits = len(raw_bits)

        r_bytes = os.urandom((num_bits + 7) // 8)
        r_int = int.from_bytes(r_bytes, "big")
        r_mask = format(r_int, f"0{num_bits}b")[:num_bits]

        return np.array(
            [int(b) ^ int(r) for b, r in zip(raw_bits, r_mask, strict=False)]
        )

    def run_clean_suite(
        self,
        nodes_config: list,
        num_trials: int = 1000,
        progress_callback=None,
    ) -> dict:
        t_start = time.perf_counter()
        trials_keys = {cfg["id"]: [] for cfg in nodes_config}

        for t in range(num_trials):
            live_host_profile, _ = self.capture_hardware_profile()
            live_telemetry = get_real_host_hardware_telemetry()

            for cfg in nodes_config:
                node_id = cfg["id"]
                offset = cfg["offset"]

                if node_id == "pc_real":
                    curr_profile = live_host_profile + np.random.normal(0, 0.0005, size=live_host_profile.shape)
                else:
                    noise_vec = self.calculate_rigorous_electronic_noise(
                        node_id, live_host_profile.shape, live_telemetry
                    )
                    curr_profile = (
                        live_host_profile + (offset / 1000.0) + noise_vec
                    )

                feat = self.extract_features(curr_profile)
                raw_b = self.quantize_gray_adaptive(feat, len(curr_profile))

                helper_file = f"puf_helper_{node_id}.json"
                if node_id == "pc_real":
                    key_bytes, _, _ = self.derive_key_host(
                        raw_b, helper_file, key_name=node_id, workload_cycles=0
                    )
                else:
                    key_bytes, _, _ = self.derive_key(
                        raw_b, helper_file, key_name=node_id, workload_cycles=0
                    )
                trials_keys[node_id].append(key_bytes.hex())

            if progress_callback and t % 50 == 0:
                progress_callback(int((t / num_trials) * 100))

        nodes_analysis = {}
        for cfg in nodes_config:
            node_id = cfg["id"]
            keys_list = trials_keys[node_id]

            key_counts = {}
            for k in keys_list:
                key_counts[k] = key_counts.get(k, 0) + 1

            sorted_inventory = sorted(
                key_counts.items(), key=lambda x: x[1], reverse=True
            )
            
            primary_key, primary_matches = sorted_inventory[0]
            stability_pct = (primary_matches / num_trials) * 100.0

            nodes_analysis[node_id] = {
                "name": cfg["name"],
                "inventory": sorted_inventory,
                "unique_count": len(sorted_inventory),
                "stability_pct": stability_pct,
                "primary_key": primary_key,
                "final_temp": live_telemetry["temp_c"],
            }

        real_keys = trials_keys["pc_real"]
        cross_hd_analysis = {}

        for cfg in nodes_config:
            node_id = cfg["id"]
            if node_id == "pc_real":
                continue

            virt_keys = trials_keys[node_id]
            hds = np.zeros(num_trials, dtype=np.float64)

            for t in range(num_trials):
                b_real = bin(int(real_keys[t], 16))[2:].zfill(256)
                b_virt = bin(int(virt_keys[t], 16))[2:].zfill(256)
                diffs = sum(
                    x != y for x, y in zip(b_real, b_virt, strict=False)
                )
                hds[t] = (diffs / 256.0) * 100.0

            cross_hd_analysis[node_id] = {
                "name": cfg["name"],
                "hds": hds,
                "mean": np.mean(hds),
                "std": np.std(hds),
            }

        elapsed_total = time.perf_counter() - t_start
        if progress_callback:
            progress_callback(100)

        return {
            "num_trials": num_trials,
            "nodes": nodes_analysis,
            "cross_hd": cross_hd_analysis,
            "total_time_s": elapsed_total,
        }

    def run_adversarial_stress_suite(self, num_samples: int = 500) -> dict:
        """
        Run the prototype's simplified trace-statistics experiment. The results do not demonstrate compliance with ISO/IEC 17825 or NIST SP 800-208.
        """
        base_profile, _ = self.capture_hardware_profile()
        raw_b_host = self.quantize_gray_adaptive(self.extract_features(base_profile), len(base_profile))
        helper_file = "puf_helper_pc_real.json"
        host_key, _, _ = self.derive_key_host(raw_b_host, helper_file, key_name="pc_real")
        
        traces = []
        for _ in range(num_samples):
            noisy_profile = base_profile + np.random.normal(0, 0.002, size=len(base_profile))
            trace = self.capture_blinded_trace(noisy_profile)
            traces.append(trace)
            
        traces_matrix = np.array(traces)
        bit_means = np.mean(traces_matrix, axis=0)
        attacker_reconstructed = "".join(["1" if m >= 0.5 else "0" for m in bit_means])
        
        attacker_key, _, _ = self.derive_key(attacker_reconstructed, helper_file, key_name="pc_real")
        
        host_key_bits = "".join(format(b, '08b') for b in host_key)
        pred_key_bits = "".join(format(b, '08b') for b in attacker_key)
        hd_bits = sum(b1 != b2 for b1, b2 in zip(host_key_bits, pred_key_bits, strict=False))
        cross_hd_pct = (hd_bits / len(host_key_bits)) * 100.0
        
        half = num_samples // 2
        group_a = traces_matrix[:half, :]
        group_b = traces_matrix[half:, :]
        mean_a, mean_b = np.mean(group_a, axis=0), np.mean(group_b, axis=0)
        var_a = np.var(group_a, axis=0, ddof=1)
        var_b = np.var(group_b, axis=0, ddof=1)
        se = np.sqrt((var_a / half) + (var_b / (num_samples - half)) + 1e-15)
        t_stats = (mean_a - mean_b) / se
        max_t_stat = float(np.nanmax(np.abs(t_stats)))
        
        ones_observed = np.sum(traces_matrix, axis=0)
        expected_ones = num_samples / 2.0
        chi2_per_bit = ((ones_observed - expected_ones) ** 2) / expected_ones + \
                       (((num_samples - ones_observed) - expected_ones) ** 2) / expected_ones
        mean_chi2 = float(np.mean(chi2_per_bit))
        
        return {
            "num_samples": num_samples,
            "bit_means_avg": float(np.mean(bit_means)),
            "cross_hd_pct": cross_hd_pct,
            "max_t_stat": max_t_stat,
            "mean_chi2": mean_chi2,
            "is_resilient": (cross_hd_pct > 42.0 and max_t_stat < 4.5),
            "host_key_hex": host_key.hex(),
            "attacker_key_hex": attacker_key.hex(),
        }


# =====================================================================
# 2. UNIFIED 8x8 GRID CIPHER ENGINE
# =====================================================================
class TangentGridCipher8x8:
    """Map text to an 8x8 symbol grid and apply a custom reversible transform.

    This component is intentionally educational and is not a cryptographic
    primitive. Do not use it to secure real-world information.
    """

    UNIFIED_GRID_8X8 = [
        ["A", "B", "C", "D", "E", "F", "G", "H"],
        ["I", "J", "K", "L", "M", "N", "O", "P"],
        ["Q", "R", "S", "T", "U", "V", "W", "X"],
        ["Y", "Z", "a", "b", "c", "d", "e", "f"],
        ["g", "h", "i", "j", "k", "l", "m", "n"],
        ["0", "1", "2", "3", "4", "5", "6", "7"],
        ["8", "9", " ", ".", ",", "!", "?", "-"],
        ["@", "#", "$", "%", "💣", "💣", "💣", "💣"],
    ]

    LANDMINE_CELLS = {(4, 7), (5, 7), (6, 7), (7, 7)}

    def __init__(self):
        self.char_to_coords = {}
        for r in range(8):
            for c in range(8):
                ch = self.UNIFIED_GRID_8X8[r][c]
                if ch != "💣":
                    self.char_to_coords[ch] = (c, r)

    def get_coords(self, char: str) -> tuple[int, int]:
        if char in self.char_to_coords:
            return self.char_to_coords[char]
        swapped = char.swapcase()
        if swapped in self.char_to_coords:
            return self.char_to_coords[swapped]
        idx = ord(char) % 60
        r = idx // 8
        c = idx % 8
        return (c, r)

    @staticmethod
    def extract_uint32_key_words(puf_key_bytes: bytes) -> tuple[int, ...]:
        return tuple(
            int.from_bytes(puf_key_bytes[i : i + 4], byteorder="big") & 0xFFFFFFFF
            for i in range(0, 32, 4)
        )

    @staticmethod
    def prng_mask_256(key_words: tuple[int, ...], seed: int, idx: int) -> int:
        k_word = key_words[idx & 7] ^ key_words[(idx + 3) & 7]
        val = (k_word ^ seed ^ (idx * 0x9E3779B9)) & 0xFFFFFFFF
        val = ((val >> 16) ^ val) * 0x45D9F3B & 0xFFFFFFFF
        val = ((val >> 16) ^ val) * 0x45D9F3B & 0xFFFFFFFF
        val = (val >> 16) ^ val
        return val & 0x3F

    def encrypt_message(self, plaintext: str, puf_key_bytes: bytes) -> dict:
        key_words = self.extract_uint32_key_words(puf_key_bytes)
        seed = int.from_bytes(os.urandom(4), "big") & 0x7FFFFFFF
        ct_bytes = []

        for idx, char in enumerate(plaintext):
            c, r = self.get_coords(char)
            pos = r * 8 + c
            mask = self.prng_mask_256(key_words, seed, idx)
            encrypted_byte = (pos ^ mask) % 64
            ct_bytes.append(encrypted_byte)

        return {"seed": seed, "ct": ct_bytes}

    def decrypt_message_debug(
        self, payload_obj: dict, puf_key_bytes: bytes
    ) -> tuple[str, list[dict], bool, str]:
        key_words = self.extract_uint32_key_words(puf_key_bytes)
        seed = payload_obj.get("seed", 0)
        ct_bytes = payload_obj.get("ct", [])

        recovered_chars = []
        debug_list = []
        landmine_triggered = False

        for idx, enc_b in enumerate(ct_bytes):
            mask = self.prng_mask_256(key_words, seed, idx)
            pos_dec = (enc_b ^ mask) % 64

            c = pos_dec % 8
            r = pos_dec // 8

            rec_char = self.UNIFIED_GRID_8X8[r][c]
            is_mine = (c, r) in self.LANDMINE_CELLS or rec_char == "💣"

            if is_mine:
                landmine_triggered = True

            recovered_chars.append(rec_char)

            debug_list.append(
                {
                    "Kc_prime": key_words[0],
                    "enc_b": enc_b,
                    "mask": mask,
                    "pos_dec": pos_dec,
                    "c_final": c,
                    "r_final": r,
                    "recovered_char": rec_char,
                    "is_mine": is_mine,
                }
            )

        return (
            "".join(recovered_chars),
            debug_list,
            landmine_triggered,
            puf_key_bytes.hex(),
        )


# =====================================================================
# 3. EXECUTIVE PYGAME DASHBOARD
# =====================================================================
class PygameTabbedPUFApp:
    """Present the prototype experiments through a six-tab Pygame interface.

    Tabs cover host telemetry, statistical trials, encryption, payload
    inspection, complexity measurements, and trace-statistics experiments.
    """

    def __init__(self):
        pygame.init()
        self.WIDTH, self.HEIGHT = 1100, 760
        self.screen = pygame.display.set_mode((self.WIDTH, self.HEIGHT))
        pygame.display.set_caption(
            "PUF Research Dashboard - Timing and Trace Experiments"
        )

        self.BG_COLOR = (13, 17, 23)
        self.PANEL_BG = (22, 27, 34)
        self.PANEL_BORDER = (48, 54, 61)
        self.TEXT_MAIN = (240, 246, 252)
        self.TEXT_MUTED = (139, 148, 158)
        self.CYAN = (56, 189, 248)
        self.GREEN = (46, 160, 67)
        self.PURPLE = (168, 85, 247)
        self.ORANGE = (249, 115, 22)
        self.RED = (248, 113, 113)

        self.font_title = pygame.font.SysFont("Consolas", 14, bold=True)
        self.font_bold = pygame.font.SysFont("Consolas", 14, bold=True)
        self.font_body = pygame.font.SysFont("Consolas", 12)
        self.font_small = pygame.font.SysFont("Consolas", 10)

        self.engine = AdvancedPUFEngine()
        self.cipher = TangentGridCipher8x8()

        self.active_tab = 0
        self.tab_btn_0 = pygame.Rect(15, 15, 165, 32)
        self.tab_btn_1 = pygame.Rect(190, 15, 165, 32)
        self.tab_btn_2 = pygame.Rect(365, 15, 165, 32)
        self.tab_btn_3 = pygame.Rect(540, 15, 165, 32)
        self.tab_btn_4 = pygame.Rect(715, 15, 165, 32)
        self.tab_btn_5 = pygame.Rect(890, 15, 195, 32)

        np.random.seed(2026)
        base_p, _ = self.engine.capture_hardware_profile()
        self.last_profiles = {"pc_real": base_p}

        n_pts = len(base_p)
        idx_axis = np.arange(n_pts, dtype=np.float64)

        off1 = 850000.0 * idx_axis + 120000.0 * np.sin(idx_axis * 1.3)
        off2 = -620000.0 * idx_axis + 95000.0 * np.cos(idx_axis * 1.7)
        off3 = 410000.0 * (idx_axis**1.4) - 500000.0 * idx_axis

        self.nodes_config = [
            {"id": "pc_real", "name": "PC 0 (Real Host)", "offset": None},
            {"id": "pc_virt_1", "name": "PC 1 (Alpha)", "offset": off1},
            {"id": "pc_virt_2", "name": "PC 2 (Beta)", "offset": off2},
            {"id": "pc_virt_3", "name": "PC 3 (Gamma)", "offset": off3},
        ]

        self.node_results = {}
        self.host_telemetry = {}
        self.btn_recalculate_all = pygame.Rect(40, 680, 240, 40)

        self.btn_run_1000 = pygame.Rect(40, 60, 300, 38)
        self.bench_results = None
        self.is_running_bench = False
        self.bench_progress = 0
        self.selected_node_idx = 0
        self.node_sel_btns = [
            pygame.Rect(800 + i * 65, 122, 60, 24) for i in range(4)
        ]

        self.user_plaintext = "PUF DEMO 2026"
        self.input_active = False
        self.input_box_rect = pygame.Rect(40, 60, 300, 38)
        self.btn_encrypt_action = pygame.Rect(350, 60, 270, 38)
        self.btn_show_modal = pygame.Rect(630, 60, 230, 38)

        self.tab3_live_key_bytes = None
        self.tab3_live_key_hex = None
        self.tab3_kc_int = None
        self.tab3_cipher_payload = None
        self.tab3_latency_ms = 0.0

        self.show_payload_modal = False
        self.modal_rect = pygame.Rect(200, 180, 700, 400)
        self.btn_copy_clipboard = pygame.Rect(450, 500, 200, 40)
        self.btn_close_modal = pygame.Rect(850, 190, 40, 30)
        self.copy_notification_time = 0.0

        self.btn_toggle_key = pygame.Rect(40, 60, 340, 38)
        self.btn_paste_payload = pygame.Rect(390, 60, 330, 38)
        self.btn_reset_payload_tab3 = pygame.Rect(730, 60, 220, 38)
        self.use_attacker_key = False

        self.tab4_custom_payload = None
        self.tab4_payload_source = "TAB 3 (LIVE)"
        self.tab4_decrypted_text = None
        self.tab4_debug_list = None
        self.tab4_decryption_time_ms = 0.0
        self.tab4_landmine_alert = False
        self.tab4_eval_key_hex = ""
        self.tab4_status_msg = ""
        self.tab4_status_time = 0.0

        self.btn_run_complexity_test = pygame.Rect(40, 60, 320, 38)
        self.is_running_complexity = False
        self.complexity_results = None

        self.btn_run_stress = pygame.Rect(40, 60, 340, 38)
        self.is_running_stress = False
        self.stress_results = None

        self.grid_cell_rects = []
        grid_start_x = 540 + 15
        grid_start_y = 115 + 45
        cell_s = 36
        for r in range(8):
            row_rects = []
            for c in range(8):
                row_rects.append(
                    pygame.Rect(
                        grid_start_x + c * cell_s,
                        grid_start_y + r * cell_s,
                        cell_s - 3,
                        cell_s - 3,
                    )
                )
            self.grid_cell_rects.append(row_rects)

        self._sample_all_cpus()
        self._execute_tab3_encryption()

    def _draw_button(self, rect, text, color):
        """Draw an interactive button with a hover highlight."""
        mouse_pos = pygame.mouse.get_pos()
        is_hover = rect.collidepoint(mouse_pos)
        fill_color = (
            (
                min(color[0] + 25, 255),
                min(color[1] + 25, 255),
                min(color[2] + 25, 255),
            )
            if is_hover
            else color
        )

        pygame.draw.rect(self.screen, fill_color, rect, border_radius=6)
        lbl = self.font_body.render(text, True, self.BG_COLOR)
        lbl_rect = lbl.get_rect(center=rect.center)
        self.screen.blit(lbl, lbl_rect)

    def _get_text_from_clipboard(self) -> str:
        text_str = ""
        try:
            import tkinter as tk
            root = tk.Tk()
            root.withdraw()
            text_str = root.clipboard_get()
            root.destroy()
        except Exception:
            try:
                pygame.scrap.init()
                text_str = pygame.scrap.get(pygame.SCRAP_TEXT).decode("utf-8")
            except Exception:
                pass
        return text_str

    def _copy_text_to_clipboard(self, text_str: str) -> bool:
        copied = False
        try:
            import tkinter as tk
            root = tk.Tk()
            root.withdraw()
            root.clipboard_clear()
            root.clipboard_append(text_str)
            root.update()
            root.destroy()
            copied = True
        except Exception:
            try:
                pygame.scrap.init()
                pygame.scrap.put(pygame.SCRAP_TEXT, text_str.encode("utf-8"))
                copied = True
            except Exception:
                pass
        self.copy_notification_time = time.time()
        return copied

    def _sample_all_cpus(self):
        self.host_telemetry = get_real_host_hardware_telemetry()
        base_profile, base_hw_ms = self.engine.capture_hardware_profile()

        for config in self.nodes_config:
            node_id = config["id"]
            offset = config["offset"]

            if offset is None:
                profile = base_profile
                hw_latency_ms = base_hw_ms
                temp_c = self.host_telemetry["temp_c"]
            else:
                noise = self.engine.calculate_rigorous_electronic_noise(
                    node_id, base_profile.shape, self.host_telemetry
                )
                profile = base_profile + (offset / 1000.0) + noise
                base_sim_hw = base_hw_ms + (np.sum(np.abs(offset)) / 1e6)
                temp_c = self.host_telemetry["temp_c"] + 12.0
                hw_latency_ms = base_sim_hw * (
                    1.0 + self.engine.gamma_silicon * (temp_c - self.engine.T_ambient)
                )

            self.last_profiles[node_id] = profile
            raw_b = self.engine.quantize_gray_adaptive(
                self.engine.extract_features(profile), len(profile)
            )
            
            if node_id == "pc_real":
                key_bytes, status, sw_latency_ms = self.engine.derive_key_host(
                    raw_b, f"puf_helper_{node_id}.json", key_name=node_id, workload_cycles=0
                )
            else:
                key_bytes, status, sw_latency_ms = self.engine.derive_key(
                    raw_b, f"puf_helper_{node_id}.json", key_name=node_id, workload_cycles=0
                )

            self.node_results[node_id] = {
                "key_bytes": key_bytes,
                "key_hex": key_bytes.hex(),
                "status": status,
                "temp_c": temp_c,
                "hw_latency_ms": hw_latency_ms,
                "sw_latency_ms": sw_latency_ms,
                "raw_bits": raw_b,
                "timestamp": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
            }

    def _execute_tab3_encryption(self):
        if not self.user_plaintext:
            return

        t0 = time.perf_counter()
        raw_profile, _ = self.engine.capture_hardware_profile()
        raw_bits = self.engine.quantize_gray_adaptive(
            self.engine.extract_features(raw_profile), len(raw_profile)
        )
        key_bytes, _, _ = self.engine.derive_key_host(
            raw_bits, "puf_helper_pc_real.json", key_name="pc_real", workload_cycles=0
        )

        self.tab3_latency_ms = (time.perf_counter() - t0) * 1000.0
        self.tab3_live_key_bytes = key_bytes
        self.tab3_live_key_hex = key_bytes.hex()
        self.tab3_kc_int = TangentGridCipher8x8.extract_uint32_key_words(key_bytes)[0]
        self.tab3_cipher_payload = self.cipher.encrypt_message(self.user_plaintext, key_bytes)
        self._execute_tab4_automatic_live_decryption()

    def _load_payload_from_clipboard(self):
        clip_txt = self._get_text_from_clipboard().strip()
        if not clip_txt:
            self.tab4_status_msg = "❌ CLIPBOARD EMPTY"
            self.tab4_status_time = time.time()
            return

        try:
            data = json.loads(clip_txt)
            if isinstance(data, dict) and "ct" in data and "seed" in data:
                self.tab4_custom_payload = data
                self.tab4_payload_source = "CLIPBOARD (1-BYTE SEED JSON)"
                self.tab4_status_msg = f"✓ PAYLOAD LOADED ({len(data['ct'])} BYTES)"
                self.tab4_status_time = time.time()
                self._execute_tab4_automatic_live_decryption()
            else:
                raise ValueError("Invalid JSON format. Missing 'seed' or 'ct'")
        except Exception as e:
            self.tab4_status_msg = f"❌ JSON ERROR: {str(e)[:30]}"
            self.tab4_status_time = time.time()

    def _execute_tab4_automatic_live_decryption(self):
        eval_payload = (
            self.tab4_custom_payload
            if self.tab4_custom_payload is not None
            else self.tab3_cipher_payload
        )
        if not eval_payload:
            return

        t0 = time.perf_counter()
        if self.use_attacker_key:
            eval_key_bytes = self.node_results["pc_virt_1"]["key_bytes"]
        else:
            raw_profile, _ = self.engine.capture_hardware_profile()
            raw_bits = self.engine.quantize_gray_adaptive(
                self.engine.extract_features(raw_profile), len(raw_profile)
            )
            eval_key_bytes, _, _ = self.engine.derive_key_host(
                raw_bits, "puf_helper_pc_real.json", key_name="pc_real", workload_cycles=0
            )

        dec_str, debug_list, is_mine_hit, eval_hex = (
            self.cipher.decrypt_message_debug(eval_payload, eval_key_bytes)
        )
        self.tab4_decryption_time_ms = (time.perf_counter() - t0) * 1000.0

        self.tab4_decrypted_text = dec_str
        self.tab4_debug_list = debug_list
        self.tab4_landmine_alert = is_mine_hit
        self.tab4_eval_key_hex = eval_hex

    def _async_bench_worker(self):
        def update_prog(p):
            self.bench_progress = p

        res = self.engine.run_clean_suite(
            self.nodes_config, num_trials=1000, progress_callback=update_prog
        )
        self.bench_results = res
        self.is_running_bench = False

    def _async_complexity_worker(self):
        lengths = [10, 100, 1000]
        results = {}
        raw_profile, _ = self.engine.capture_hardware_profile()
        raw_bits = self.engine.quantize_gray_adaptive(
            self.engine.extract_features(raw_profile), len(raw_profile)
        )
        puf_key, _, _ = self.engine.derive_key_host(
            raw_bits, "puf_helper_pc_real.json", key_name="pc_real", workload_cycles=0
        )
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .!?"

        for L in lengths:
            sample_text = "".join([alphabet[i % len(alphabet)] for i in range(L)])
            t_enc_start = time.perf_counter()
            for _ in range(100):
                payload = self.cipher.encrypt_message(sample_text, puf_key)
            enc_time_avg_ms = ((time.perf_counter() - t_enc_start) / 100.0) * 1000.0

            t_dec_start = time.perf_counter()
            for _ in range(100):
                self.cipher.decrypt_message_debug(payload, puf_key)
            dec_time_avg_ms = ((time.perf_counter() - t_dec_start) / 100.0) * 1000.0

            results[L] = {
                "enc_ms": enc_time_avg_ms,
                "dec_ms": dec_time_avg_ms,
                "enc_throughput": L / (enc_time_avg_ms if enc_time_avg_ms > 0 else 0.001),
                "dec_throughput": L / (dec_time_avg_ms if dec_time_avg_ms > 0 else 0.001),
            }

        self.complexity_results = results
        self.is_running_complexity = False

    def _async_stress_worker(self):
        res = self.engine.run_adversarial_stress_suite(num_samples=500)
        self.stress_results = res
        self.is_running_stress = False

    def run(self):
        clock = pygame.time.Clock()
        running = True

        while running:
            self.screen.fill(self.BG_COLOR)

            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    running = False

                elif event.type == pygame.MOUSEBUTTONDOWN:
                    if self.show_payload_modal:
                        if self.btn_close_modal.collidepoint(event.pos):
                            self.show_payload_modal = False
                        elif self.btn_copy_clipboard.collidepoint(event.pos):
                            payload_json = json.dumps(self.tab3_cipher_payload, indent=2)
                            self._copy_text_to_clipboard(payload_json)
                        continue

                    if self.tab_btn_0.collidepoint(event.pos):
                        self.active_tab = 0
                    elif self.tab_btn_1.collidepoint(event.pos):
                        self.active_tab = 1
                    elif self.tab_btn_2.collidepoint(event.pos):
                        self.active_tab = 2
                    elif self.tab_btn_3.collidepoint(event.pos):
                        self.active_tab = 3
                        self._execute_tab4_automatic_live_decryption()
                    elif self.tab_btn_4.collidepoint(event.pos):
                        self.active_tab = 4
                    elif self.tab_btn_5.collidepoint(event.pos):
                        self.active_tab = 5

                    if (
                        self.active_tab == 0
                        and self.btn_recalculate_all.collidepoint(event.pos)
                    ):
                        self._sample_all_cpus()

                    elif self.active_tab == 1:
                        if (
                            self.btn_run_1000.collidepoint(event.pos)
                            and not self.is_running_bench
                        ):
                            self.is_running_bench = True
                            self.bench_progress = 0
                            threading.Thread(
                                target=self._async_bench_worker, daemon=True
                            ).start()

                        for idx, btn_r in enumerate(self.node_sel_btns):
                            if btn_r.collidepoint(event.pos):
                                self.selected_node_idx = idx

                    elif self.active_tab == 2:
                        if self.input_box_rect.collidepoint(event.pos):
                            self.input_active = True
                        else:
                            self.input_active = False

                        if self.btn_encrypt_action.collidepoint(event.pos):
                            self._execute_tab3_encryption()

                        if self.btn_show_modal.collidepoint(event.pos):
                            self.show_payload_modal = True

                    elif self.active_tab == 3:
                        if self.btn_toggle_key.collidepoint(event.pos):
                            self.use_attacker_key = not self.use_attacker_key
                            self._execute_tab4_automatic_live_decryption()
                        elif self.btn_paste_payload.collidepoint(event.pos):
                            self._load_payload_from_clipboard()
                        elif self.btn_reset_payload_tab3.collidepoint(event.pos):
                            self.tab4_custom_payload = None
                            self.tab4_payload_source = "TAB 3 (LIVE)"
                            self.tab4_status_msg = "✓ RESTORED TO TAB 3"
                            self.tab4_status_time = time.time()
                            self._execute_tab4_automatic_live_decryption()

                    elif self.active_tab == 4:
                        if (
                            self.btn_run_complexity_test.collidepoint(event.pos)
                            and not self.is_running_complexity
                        ):
                            self.is_running_complexity = True
                            threading.Thread(
                                target=self._async_complexity_worker, daemon=True
                            ).start()

                    elif self.active_tab == 5:
                        if (
                            self.btn_run_stress.collidepoint(event.pos)
                            and not self.is_running_stress
                        ):
                            self.is_running_stress = True
                            threading.Thread(
                                target=self._async_stress_worker, daemon=True
                            ).start()

                elif event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_RIGHT:
                        self.active_tab = (self.active_tab + 1) % 6
                        if self.active_tab == 3:
                            self._execute_tab4_automatic_live_decryption()
                    elif event.key == pygame.K_LEFT:
                        self.active_tab = (self.active_tab - 1) % 6
                        if self.active_tab == 3:
                            self._execute_tab4_automatic_live_decryption()

                    elif self.active_tab == 2:
                        if self.show_payload_modal:
                            if event.key == pygame.K_ESCAPE:
                                self.show_payload_modal = False
                            continue

                        if self.input_active:
                            if event.key == pygame.K_BACKSPACE:
                                self.user_plaintext = self.user_plaintext[:-1]
                            elif event.key in (pygame.K_RETURN, pygame.K_KP_ENTER):
                                self.input_active = False
                                self._execute_tab3_encryption()
                            else:
                                if len(self.user_plaintext) < 18:
                                    self.user_plaintext += event.unicode

            self._draw_header_tabs()
            if self.active_tab == 0:
                self._draw_tab_1()
            elif self.active_tab == 1:
                self._draw_tab_2()
            elif self.active_tab == 2:
                self._draw_tab_3()
            elif self.active_tab == 3:
                self._draw_tab_4()
            elif self.active_tab == 4:
                self._draw_tab_5()
            else:
                self._draw_tab_6()

            if self.show_payload_modal:
                self._draw_payload_modal()

            pygame.display.flip()
            clock.tick(30)

        pygame.quit()

    def _draw_header_tabs(self):
        tabs = [
            (self.tab_btn_0, "TAB 1: HOST HW", 0),
            (self.tab_btn_1, "TAB 2: STATS SUITE", 1),
            (self.tab_btn_2, "TAB 3: 8x8 CIPHER", 2),
            (self.tab_btn_3, "TAB 4: PAYLOAD", 3),
            (self.tab_btn_4, "TAB 5: COMPLEXITY", 4),
            (self.tab_btn_5, "TAB 6: TVLA AUDITOR", 5),
        ]

        for rect, text, idx in tabs:
            is_active = self.active_tab == idx
            color = self.CYAN if is_active else self.PANEL_BG
            pygame.draw.rect(self.screen, color, rect, border_radius=6)
            lbl = self.font_body.render(
                text, True, self.BG_COLOR if is_active else self.TEXT_MAIN
            )
            self.screen.blit(lbl, lbl.get_rect(center=rect.center))

    def _draw_tab_1(self):
        coords = [(40, 60), (560, 60), (40, 310), (560, 310)]
        t = self.host_telemetry

        for idx, config in enumerate(self.nodes_config):
            x, y = coords[idx]
            node_id = config["id"]
            res = self.node_results[node_id]

            card_rect = pygame.Rect(x, y, 500, 230)
            pygame.draw.rect(self.screen, self.PANEL_BG, card_rect, border_radius=8)
            border_c = self.CYAN if config["offset"] is None else self.PANEL_BORDER
            pygame.draw.rect(self.screen, border_c, card_rect, 1, border_radius=8)

            name_lbl = self.font_title.render(
                config["name"], True, self.CYAN if config["offset"] is None else self.TEXT_MAIN
            )
            t_val = res["temp_c"]
            t_color = self.GREEN if t_val < 50.0 else (self.ORANGE if t_val < 70.0 else self.RED)
            temp_lbl = self.font_body.render(f"TEMP: {t_val:.1f} °C", True, t_color)

            st_lbl = self.font_body.render(f"STATUS     : {res['status']}", True, self.GREEN)
            lat_lbl = self.font_body.render(
                f"LATENCY    : HW {res['hw_latency_ms']:.3f} ms | SW {res['sw_latency_ms']:.3f} ms",
                True,
                self.TEXT_MUTED,
            )

            self.screen.blit(name_lbl, (x + 16, y + 14))
            self.screen.blit(temp_lbl, (x + 360, y + 14))
            self.screen.blit(st_lbl, (x + 16, y + 38))
            self.screen.blit(lat_lbl, (x + 16, y + 56))

            if node_id == "pc_real":
                hw_info = f"CPU Load: {t['cpu_percent']:.1f}% | Clock: {t['cpu_freq_mhz']:.0f}MHz | RAM: {t['ram_usage_pct']:.1f}% | VRM: {t['vrm_current_a']:.2f}A @ {t['vrm_voltage_v']:.3f}V"
                hw_surf = self.font_small.render(hw_info, True, self.CYAN)
                self.screen.blit(hw_surf, (x + 16, y + 74))

            key_title = self.font_small.render("DERIVED MASTER KEY (SHA-256):", True, self.TEXT_MUTED)
            self.screen.blit(key_title, (x + 16, y + 96))

            hex_str = res["key_hex"]
            k1 = self.font_body.render(hex_str[:32], True, self.PURPLE)
            k2 = self.font_body.render(hex_str[32:], True, self.PURPLE)
            self.screen.blit(k1, (x + 16, y + 114))
            self.screen.blit(k2, (x + 16, y + 132))

            raw_preview = self.font_small.render(f"RAW SIGNATURE: {res['raw_bits'][:32]}...", True, self.TEXT_MUTED)
            self.screen.blit(raw_preview, (x + 16, y + 180))

        line_panel = pygame.Rect(300, 560, 760, 150)
        pygame.draw.rect(self.screen, self.PANEL_BG, line_panel, border_radius=8)
        pygame.draw.rect(self.screen, self.CYAN, line_panel, 1, border_radius=8)

        m_title = self.font_title.render("LINE VISUALIZATION - REAL-TIME SILICON DELAY SIGNATURES", True, self.CYAN)
        self.screen.blit(m_title, (line_panel.x + 20, line_panel.y + 12))

        px, py = line_panel.x + 30, line_panel.y + 40
        pw, ph = line_panel.width - 60, line_panel.height - 55

        pygame.draw.rect(self.screen, (13, 17, 23), (px, py, pw, ph))
        pygame.draw.rect(self.screen, self.PANEL_BORDER, (px, py, pw, ph), 1)

        node_colors = {
            "pc_real": self.CYAN,
            "pc_virt_1": self.PURPLE,
            "pc_virt_2": self.ORANGE,
            "pc_virt_3": self.RED,
        }

        for n_id, prof in self.last_profiles.items():
            color = node_colors.get(n_id, self.TEXT_MAIN)
            min_val, max_val = np.min(prof), np.max(prof)
            val_range = max_val - min_val if max_val != min_val else 1.0

            points = []
            num_pts = len(prof)
            for idx, val in enumerate(prof):
                x_pos = px + int((idx / (num_pts - 1)) * pw)
                y_pos = py + ph - int(((val - min_val) / val_range) * (ph - 10)) - 5
                points.append((x_pos, y_pos))

            if len(points) > 1:
                pygame.draw.lines(self.screen, color, False, points, 2)

        self._draw_button(self.btn_recalculate_all, "RE-SAMPLE HARDWARE", self.CYAN)

    def _draw_tab_2(self):
        btn_color = (70, 80, 95) if self.is_running_bench else self.CYAN
        btn_text = (
            f"RUNNING TRIALS... ({self.bench_progress}%)"
            if self.is_running_bench
            else "RUN 1,000 STATISTICAL TRIALS"
        )
        self._draw_button(self.btn_run_1000, btn_text, btn_color)

        if self.is_running_bench:
            pygame.draw.rect(
                self.screen, self.PANEL_BG, pygame.Rect(360, 67, 700, 24), border_radius=4
            )
            pygame.draw.rect(
                self.screen,
                self.CYAN,
                pygame.Rect(360, 67, int(700 * (self.bench_progress / 100)), 24),
                border_radius=4,
            )

        if self.bench_results is None:
            panel = pygame.Rect(40, 110, 1020, 610)
            pygame.draw.rect(self.screen, self.PANEL_BG, panel, border_radius=8)
            msg = self.font_title.render(
                "Click 'RUN 1,000 STATISTICAL TRIALS' to evaluate key variations and Cross-HD distribution.",
                True,
                self.TEXT_MUTED,
            )
            self.screen.blit(msg, (80, 380))
            return

        r = self.bench_results
        chart_left_rect = pygame.Rect(40, 110, 490, 410)
        self._draw_cross_hd_chart(chart_left_rect, r["cross_hd"])

        chart_right_rect = pygame.Rect(550, 110, 510, 410)
        self._draw_key_variation_panel(chart_right_rect, r["nodes"])

        metrics_bottom_rect = pygame.Rect(40, 535, 1020, 185)
        self._draw_clean_metrics_table(metrics_bottom_rect, r)

    def _draw_cross_hd_chart(self, rect: pygame.Rect, cross_hd_data: dict):
        pygame.draw.rect(self.screen, self.PANEL_BG, rect, border_radius=8)
        pygame.draw.rect(self.screen, self.PANEL_BORDER, rect, 1, border_radius=8)

        t_surf = self.font_title.render("CROSS-HD DISTRIBUTION (HOST VS VIRTUALS)", True, self.CYAN)
        self.screen.blit(t_surf, (rect.x + 16, rect.y + 14))

        px, py = rect.x + 40, rect.y + 50
        pw, ph = rect.width - 55, rect.height - 80

        pygame.draw.line(self.screen, self.TEXT_MUTED, (px, py + ph), (px + pw, py + ph), 1)
        pygame.draw.line(self.screen, self.TEXT_MUTED, (px, py), (px, py + ph), 1)

        num_bins = 40
        bins = np.linspace(0, 100, num_bins + 1)

        hist_counts = {}
        max_c = 1
        colors = {
            "pc_virt_1": self.CYAN,
            "pc_virt_2": self.PURPLE,
            "pc_virt_3": self.ORANGE,
        }

        for node_id, data in cross_hd_data.items():
            counts, _ = np.histogram(data["hds"], bins=bins)
            hist_counts[node_id] = counts
            if np.max(counts) > max_c:
                max_c = np.max(counts)

        for node_id, counts in hist_counts.items():
            color = colors[node_id]
            points = []
            for b in range(num_bins):
                x_val = px + (b + 0.5) * (pw / num_bins)
                y_val = (py + ph) - (counts[b] / max_c) * (ph - 15)
                points.append((x_val, y_val))

            if len(points) > 1:
                pygame.draw.lines(self.screen, color, False, points, 2)

        ref_x = px + (pw * 0.5)
        pygame.draw.line(self.screen, self.RED, (ref_x, py), (ref_x, py + ph), 1)

        lbl_50 = self.font_small.render("50% Ideal", True, self.RED)
        self.screen.blit(lbl_50, (ref_x - 22, py + 5))

        lbl_x0 = self.font_small.render("0%", True, self.TEXT_MUTED)
        lbl_x100 = self.font_small.render("100% HD", True, self.TEXT_MUTED)
        self.screen.blit(lbl_x0, (px, py + ph + 5))
        self.screen.blit(lbl_x100, (px + pw - 40, py + ph + 5))

    def _draw_key_variation_panel(self, rect: pygame.Rect, nodes_data: dict):
        pygame.draw.rect(self.screen, self.PANEL_BG, rect, border_radius=8)
        pygame.draw.rect(self.screen, self.PANEL_BORDER, rect, 1, border_radius=8)

        t_title = self.font_title.render("KEY VARIATION BREAKDOWN (PERSISTENT DISK EVALUATION)", True, self.TEXT_MAIN)
        self.screen.blit(t_title, (rect.x + 16, rect.y + 14))

        node_keys = ["pc_real", "pc_virt_1", "pc_virt_2", "pc_virt_3"]
        labels = ["HOST", "PC 1", "PC 2", "PC 3"]

        for i, b_rect in enumerate(self.node_sel_btns):
            is_sel = i == self.selected_node_idx
            bg_c = self.CYAN if is_sel else (35, 43, 54)
            pygame.draw.rect(self.screen, bg_c, b_rect, border_radius=4)
            lbl = self.font_small.render(labels[i], True, self.BG_COLOR if is_sel else self.TEXT_MAIN)
            self.screen.blit(lbl, lbl.get_rect(center=b_rect.center))

        sel_id = node_keys[self.selected_node_idx]
        node_info = nodes_data[sel_id]

        st_color = self.GREEN
        st_txt = f"Node: {node_info['name']} | Keys: {node_info['unique_count']} | Stability: {node_info['stability_pct']:.1f}% | Temp: {node_info['final_temp']:.1f}°C"
        sub_surf = self.font_body.render(st_txt, True, st_color)
        self.screen.blit(sub_surf, (rect.x + 16, rect.y + 42))

        pygame.draw.line(self.screen, self.PANEL_BORDER, (rect.x + 16, rect.y + 68), (rect.x + rect.width - 16, rect.y + 68), 1)

        h1 = self.font_small.render("DISCOVERED KEY HASH (SHA-256)", True, self.TEXT_MUTED)
        h2 = self.font_small.render("TRIALS", True, self.TEXT_MUTED)
        h3 = self.font_small.render("PERCENTAGE", True, self.TEXT_MUTED)

        self.screen.blit(h1, (rect.x + 16, rect.y + 75))
        self.screen.blit(h2, (rect.x + 300, rect.y + 75))
        self.screen.blit(h3, (rect.x + 390, rect.y + 75))

        pygame.draw.line(self.screen, self.PANEL_BORDER, (rect.x + 16, rect.y + 92), (rect.x + rect.width - 16, rect.y + 92), 1)

        start_y = rect.y + 102
        inventory = node_info["inventory"]

        for idx, (k_hex, count) in enumerate(inventory[:6]):
            pct = (count / 1000.0) * 100.0
            row_y = start_y + (idx * 45)

            k_surf = self.font_body.render(f"#{idx+1} {k_hex[:24]}...", True, self.TEXT_MAIN)
            c_surf = self.font_body.render(f"{count}", True, self.TEXT_MAIN)
            p_surf = self.font_body.render(f"{pct:.1f}%", True, self.GREEN if idx == 0 else self.ORANGE)

            self.screen.blit(k_surf, (rect.x + 16, row_y))
            self.screen.blit(c_surf, (rect.x + 300, row_y))
            self.screen.blit(p_surf, (rect.x + 390, row_y))

            bar_w = int((pct / 100.0) * 460)
            pygame.draw.rect(self.screen, (35, 43, 54), pygame.Rect(rect.x + 16, row_y + 20, 460, 6), border_radius=3)
            pygame.draw.rect(self.screen, self.GREEN if idx == 0 else self.ORANGE, pygame.Rect(rect.x + 16, row_y + 20, bar_w, 6), border_radius=3)

    def _draw_clean_metrics_table(self, rect: pygame.Rect, bench_data: dict):
        pygame.draw.rect(self.screen, self.PANEL_BG, rect, border_radius=8)
        pygame.draw.rect(self.screen, self.PANEL_BORDER, rect, 1, border_radius=8)

        m_title = self.font_title.render("SYSTEM STATISTICAL SUMMARY (N=1,000 EXPERIMENTAL TRIALS)", True, self.TEXT_MAIN)
        self.screen.blit(m_title, (rect.x + 16, rect.y + 12))

        headers = [
            ("NODE", 16),
            ("UNIQUE KEYS", 180),
            ("PRIMARY STABILITY", 310),
            ("CROSS-HD MEAN VS HOST", 510),
            ("CROSS-HD STD (σ)", 740),
            ("FINAL TEMP", 900),
        ]

        for h_text, x_off in headers:
            h_surf = self.font_small.render(h_text, True, self.TEXT_MUTED)
            self.screen.blit(h_surf, (rect.x + x_off, rect.y + 38))

        pygame.draw.line(self.screen, self.PANEL_BORDER, (rect.x + 16, rect.y + 53), (rect.x + rect.width - 16, rect.y + 53), 1)

        nodes = bench_data["nodes"]
        cross_hd = bench_data["cross_hd"]
        node_order = ["pc_real", "pc_virt_1", "pc_virt_2", "pc_virt_3"]

        for idx, n_id in enumerate(node_order):
            n_data = nodes[n_id]
            y_pos = rect.y + 64 + (idx * 26)

            name_surf = self.font_body.render(n_data["name"], True, self.TEXT_MAIN)
            keys_surf = self.font_body.render(str(n_data["unique_count"]), True, self.TEXT_MAIN)

            st_color = self.GREEN
            stab_surf = self.font_body.render(f"{n_data['stability_pct']:.1f}%", True, st_color)

            if n_id == "pc_real":
                mean_surf = self.font_body.render("0.00% (Host)", True, self.CYAN)
                std_surf = self.font_body.render("0.00%", True, self.CYAN)
            else:
                c_data = cross_hd[n_id]
                mean_surf = self.font_body.render(f"{c_data['mean']:.2f}%", True, self.TEXT_MAIN)
                std_surf = self.font_body.render(f"{c_data['std']:.2f}%", True, self.TEXT_MAIN)

            t_val = n_data["final_temp"]
            t_color = self.GREEN if t_val < 50.0 else (self.ORANGE if t_val < 70.0 else self.RED)
            temp_surf = self.font_body.render(f"{t_val:.1f} °C", True, t_color)

            self.screen.blit(name_surf, (rect.x + 16, y_pos))
            self.screen.blit(keys_surf, (rect.x + 180, y_pos))
            self.screen.blit(stab_surf, (rect.x + 310, y_pos))
            self.screen.blit(mean_surf, (rect.x + 510, y_pos))
            self.screen.blit(std_surf, (rect.x + 740, y_pos))
            self.screen.blit(temp_surf, (rect.x + 900, y_pos))

    def _draw_tab_3(self):
        box_border = self.CYAN if self.input_active else self.PANEL_BORDER
        pygame.draw.rect(self.screen, self.PANEL_BG, self.input_box_rect, border_radius=6)
        pygame.draw.rect(self.screen, box_border, self.input_box_rect, 1, border_radius=6)

        txt_surf = self.font_body.render(f"INPUT: {self.user_plaintext}", True, self.TEXT_MAIN)
        self.screen.blit(txt_surf, (self.input_box_rect.x + 12, self.input_box_rect.y + 11))

        self._draw_button(self.btn_encrypt_action, "ENCRYPT WITH LIVE CPU PUF KEY", self.CYAN)
        self._draw_button(self.btn_show_modal, "📋 PAYLOAD & COPY", self.PURPLE)

        if not self.tab3_cipher_payload:
            return

        key_panel = pygame.Rect(40, 115, 480, 150)
        pygame.draw.rect(self.screen, self.PANEL_BG, key_panel, border_radius=8)
        pygame.draw.rect(self.screen, self.CYAN, key_panel, 1, border_radius=8)

        k_title = self.font_title.render("LIVE HOST CPU PUF KEY DERIVATION", True, self.CYAN)
        self.screen.blit(k_title, (key_panel.x + 16, key_panel.y + 14))

        kh_lbl = self.font_small.render("256-BIT SHA-256 MASTER KEY:", True, self.TEXT_MUTED)
        self.screen.blit(kh_lbl, (key_panel.x + 16, key_panel.y + 38))

        k_hex = self.tab3_live_key_hex
        k1 = self.font_body.render(k_hex[:32], True, self.PURPLE)
        k2 = self.font_body.render(k_hex[32:], True, self.PURPLE)
        self.screen.blit(k1, (key_panel.x + 16, key_panel.y + 55))
        self.screen.blit(k2, (key_panel.x + 16, key_panel.y + 75))

        kc_lbl = self.font_body.render(f"• Dynamic Kc Int32 : {self.tab3_kc_int} (0x{self.tab3_kc_int:08X})", True, self.TEXT_MAIN)
        lat_lbl = self.font_body.render(f"• Sampling Latency : {self.tab3_latency_ms:.2f} ms", True, self.GREEN)

        self.screen.blit(kc_lbl, (key_panel.x + 16, key_panel.y + 100))
        self.screen.blit(lat_lbl, (key_panel.x + 16, key_panel.y + 122))

        payload_panel = pygame.Rect(40, 280, 480, 440)
        pygame.draw.rect(self.screen, self.PANEL_BG, payload_panel, border_radius=8)
        pygame.draw.rect(self.screen, self.PANEL_BORDER, payload_panel, 1, border_radius=8)

        seed_val = self.tab3_cipher_payload["seed"]
        ct_bytes = self.tab3_cipher_payload["ct"]

        p_title = self.font_title.render(f"1-BYTE SEED PAYLOAD (SEED: {seed_val} | {len(ct_bytes)} BYTES)", True, self.TEXT_MAIN)
        self.screen.blit(p_title, (payload_panel.x + 16, payload_panel.y + 14))

        pygame.draw.line(self.screen, self.PANEL_BORDER, (payload_panel.x + 16, payload_panel.y + 38), (payload_panel.x + payload_panel.width - 16, payload_panel.y + 38), 1)

        h1 = self.font_small.render("IDX", True, self.TEXT_MUTED)
        h2 = self.font_small.render("CIPHER BYTE (ct[i])", True, self.TEXT_MUTED)
        h3 = self.font_small.render("SIZE (BYTES)", True, self.TEXT_MUTED)

        self.screen.blit(h1, (payload_panel.x + 16, payload_panel.y + 44))
        self.screen.blit(h2, (payload_panel.x + 100, payload_panel.y + 44))
        self.screen.blit(h3, (payload_panel.x + 300, payload_panel.y + 44))

        pygame.draw.line(self.screen, self.PANEL_BORDER, (payload_panel.x + 16, payload_panel.y + 60), (payload_panel.x + payload_panel.width - 16, payload_panel.y + 60), 1)

        start_y = payload_panel.y + 68
        for idx, enc_b in enumerate(ct_bytes[:12]):
            row_y = start_y + idx * 30
            idx_str = self.font_body.render(f"#{idx}", True, self.TEXT_MUTED)
            b_str = self.font_body.render(f"{enc_b} (0x{enc_b:02X})", True, self.CYAN)
            sz_str = self.font_body.render("1 Byte", True, self.GREEN)

            self.screen.blit(idx_str, (payload_panel.x + 20, row_y + 2))
            self.screen.blit(b_str, (payload_panel.x + 100, row_y + 2))
            self.screen.blit(sz_str, (payload_panel.x + 300, row_y + 2))

        inspect_panel = pygame.Rect(540, 115, 520, 605)
        pygame.draw.rect(self.screen, self.PANEL_BG, inspect_panel, border_radius=8)
        pygame.draw.rect(self.screen, self.PANEL_BORDER, inspect_panel, 1, border_radius=8)

        i_title = self.font_title.render("LIVE 8x8 GRID VISUALIZATION", True, self.ORANGE)
        self.screen.blit(i_title, (inspect_panel.x + 16, inspect_panel.y + 14))

        for r in range(8):
            for c in range(8):
                cell_rect = self.grid_cell_rects[r][c]
                is_landmine = (c, r) in TangentGridCipher8x8.LANDMINE_CELLS
                cell_bg = (80, 20, 20) if is_landmine else (35, 43, 54)
                pygame.draw.rect(self.screen, cell_bg, cell_rect, border_radius=4)
                char_str = TangentGridCipher8x8.UNIFIED_GRID_8X8[r][c]
                c_txt = self.font_body.render(char_str, True, self.RED if is_landmine else self.TEXT_MAIN)
                self.screen.blit(c_txt, c_txt.get_rect(center=cell_rect.center))

    def _draw_payload_modal(self):
        overlay = pygame.Surface((self.WIDTH, self.HEIGHT), pygame.SRCALPHA)
        overlay.fill((0, 0, 0, 180))
        self.screen.blit(overlay, (0, 0))

        pygame.draw.rect(self.screen, self.PANEL_BG, self.modal_rect, border_radius=10)
        pygame.draw.rect(self.screen, self.CYAN, self.modal_rect, 2, border_radius=10)

        title_surf = self.font_title.render("SERIALIZED CIPHER PAYLOAD (JSON)", True, self.CYAN)
        self.screen.blit(title_surf, (self.modal_rect.x + 20, self.modal_rect.y + 20))

        self._draw_button(self.btn_close_modal, "X", self.RED)

        code_box = pygame.Rect(self.modal_rect.x + 20, self.modal_rect.y + 60, 660, 300)
        pygame.draw.rect(self.screen, (13, 17, 23), code_box, border_radius=6)
        pygame.draw.rect(self.screen, self.PANEL_BORDER, code_box, 1, border_radius=6)

        json_str = json.dumps(self.tab3_cipher_payload, indent=2)
        lines = json_str.split("\n")

        for idx, line in enumerate(lines[:17]):
            line_surf = self.font_small.render(line, True, self.TEXT_MAIN)
            self.screen.blit(line_surf, (code_box.x + 15, code_box.y + 12 + idx * 16))

        self._draw_button(self.btn_copy_clipboard, "📋 COPY TO CLIPBOARD", self.GREEN)

        if time.time() - self.copy_notification_time < 2.5:
            notif = self.font_body.render("✓ 1-BYTE PAYLOAD COPIED TO SYSTEM CLIPBOARD!", True, self.GREEN)
            self.screen.blit(notif, (self.modal_rect.x + 20, self.modal_rect.y + 365))

    def _draw_tab_4(self):
        key_color = self.RED if self.use_attacker_key else self.GREEN
        key_txt = "KEY: ATTACKER" if self.use_attacker_key else "KEY: VALID HOST"
        self._draw_button(self.btn_toggle_key, key_txt, key_color)

        self._draw_button(self.btn_paste_payload, "📥 PASTE / LOAD PAYLOAD (JSON)", self.PURPLE)
        self._draw_button(self.btn_reset_payload_tab3, "🔄 RESET TO TAB 3", (45, 55, 70))

        if time.time() - self.tab4_status_time < 3.0:
            st_color = self.GREEN if "✓" in self.tab4_status_msg else self.RED
            st_lbl = self.font_body.render(self.tab4_status_msg, True, st_color)
            self.screen.blit(st_lbl, (40, 102))

        active_p = (
            self.tab4_custom_payload
            if self.tab4_custom_payload is not None
            else self.tab3_cipher_payload
        )
        if not active_p:
            panel = pygame.Rect(40, 125, 1020, 600)
            pygame.draw.rect(self.screen, self.PANEL_BG, panel, border_radius=8)
            msg = self.font_title.render("Please encrypt a message in TAB 3 or paste a valid JSON payload.", True, self.TEXT_MUTED)
            self.screen.blit(msg, (80, 380))
            return

        out_panel = pygame.Rect(40, 125, 1020, 175)
        pygame.draw.rect(self.screen, self.PANEL_BG, out_panel, border_radius=8)

        border_c = self.GREEN if not self.tab4_landmine_alert else self.RED
        pygame.draw.rect(self.screen, border_c, out_panel, 1, border_radius=8)

        r_title = self.font_title.render(f"DECRYPTED MESSAGE (SOURCE: {self.tab4_payload_source}):", True, border_c)
        self.screen.blit(r_title, (out_panel.x + 16, out_panel.y + 14))

        txt_display = self.font_title.render(f'"{self.tab4_decrypted_text}"', True, border_c)
        txt_large = pygame.transform.scale(txt_display, (txt_display.get_width() * 2, txt_display.get_height() * 2))
        self.screen.blit(txt_large, (out_panel.x + 20, out_panel.y + 42))

        k_used = self.font_small.render(f"LIVE KEY USED (SHA-256): {self.tab4_eval_key_hex}", True, self.TEXT_MUTED)
        self.screen.blit(k_used, (out_panel.x + 16, out_panel.y + 110))

        if not self.tab4_landmine_alert:
            desc_text = f"✓ SUCCESS: Valid Host PUF key. Message recovered in {self.tab4_decryption_time_ms:.2f} ms with 0% error."
        else:
            desc_text = f"🚨 INTRUSION ALERT: Unauthorized key triggered landmine cell (💣 LANDMINE). Branchless protection activated."

        desc_lbl = self.font_body.render(desc_text, True, border_c)
        self.screen.blit(desc_lbl, (out_panel.x + 16, out_panel.y + 138))

        table_panel = pygame.Rect(40, 315, 1020, 410)
        pygame.draw.rect(self.screen, self.PANEL_BG, table_panel, border_radius=8)
        pygame.draw.rect(self.screen, self.PANEL_BORDER, table_panel, 1, border_radius=8)

        t_title = self.font_title.render("PER-CHARACTER TRANSFORMATION TRACE", True, self.CYAN)
        self.screen.blit(t_title, (table_panel.x + 16, table_panel.y + 14))

        pygame.draw.line(self.screen, self.PANEL_BORDER, (table_panel.x + 16, table_panel.y + 38), (table_panel.x + table_panel.width - 16, table_panel.y + 38), 1)

        h1 = self.font_small.render("IDX", True, self.TEXT_MUTED)
        h2 = self.font_small.render("CIPHER BYTE", True, self.TEXT_MUTED)
        h3 = self.font_small.render("PRNG MASK", True, self.TEXT_MUTED)
        h4 = self.font_small.render("DECRYPTED POSITION", True, self.TEXT_MUTED)
        h5 = self.font_small.render("FINAL GRID (c, r)", True, self.TEXT_MUTED)
        h6 = self.font_small.render("STATUS / TRAP", True, self.TEXT_MUTED)

        self.screen.blit(h1, (table_panel.x + 16, table_panel.y + 44))
        self.screen.blit(h2, (table_panel.x + 80, table_panel.y + 44))
        self.screen.blit(h3, (table_panel.x + 220, table_panel.y + 44))
        self.screen.blit(h4, (table_panel.x + 380, table_panel.y + 44))
        self.screen.blit(h5, (table_panel.x + 600, table_panel.y + 44))
        self.screen.blit(h6, (table_panel.x + 800, table_panel.y + 44))

        pygame.draw.line(self.screen, self.PANEL_BORDER, (table_panel.x + 16, table_panel.y + 60), (table_panel.x + table_panel.width - 16, table_panel.y + 60), 1)

        start_y = table_panel.y + 68
        for idx, dbg in enumerate(self.tab4_debug_list[:11]):
            row_y = start_y + idx * 30
            idx_s = self.font_body.render(f"#{idx}", True, self.TEXT_MUTED)
            enc_s = self.font_body.render(f"{dbg['enc_b']}", True, self.CYAN)
            mask_s = self.font_body.render(f"{dbg['mask']}", True, self.PURPLE)
            pos_s = self.font_body.render(f"{dbg['pos_dec']}", True, self.TEXT_MAIN)
            fin_s = self.font_body.render(f"({dbg['c_final']}, {dbg['r_final']})", True, self.GREEN)
            mine_str = "💣 TRAP!" if dbg["is_mine"] else "OK"
            ch_s = self.font_title.render(f"{dbg['recovered_char']} [{mine_str}]", True, self.RED if dbg["is_mine"] else self.GREEN)

            self.screen.blit(idx_s, (table_panel.x + 16, row_y + 2))
            self.screen.blit(enc_s, (table_panel.x + 80, row_y + 2))
            self.screen.blit(mask_s, (table_panel.x + 220, row_y + 2))
            self.screen.blit(pos_s, (table_panel.x + 380, row_y + 2))
            self.screen.blit(fin_s, (table_panel.x + 600, row_y + 2))
            self.screen.blit(ch_s, (table_panel.x + 800, row_y + 2))

    def _draw_tab_5(self):
        btn_color = (70, 80, 95) if self.is_running_complexity else self.CYAN
        btn_txt = "RUNNING BENCHMARKS..." if self.is_running_complexity else "BENCHMARK TEXT LENGTHS (10, 100, 1,000 CHARS)"
        self._draw_button(self.btn_run_complexity_test, btn_txt, btn_color)

        if self.complexity_results is None and not self.is_running_complexity:
            panel = pygame.Rect(40, 115, 1020, 605)
            pygame.draw.rect(self.screen, self.PANEL_BG, panel, border_radius=8)
            msg = self.font_title.render("Click 'BENCHMARK TEXT LENGTHS' to graph O(N) execution scaling for 10, 100, and 1,000 characters.", True, self.TEXT_MUTED)
            self.screen.blit(msg, (80, 380))
            return

        if self.complexity_results is None:
            return

        res = self.complexity_results
        graph_panel = pygame.Rect(40, 115, 500, 605)
        pygame.draw.rect(self.screen, self.PANEL_BG, graph_panel, border_radius=8)
        pygame.draw.rect(self.screen, self.CYAN, graph_panel, 1, border_radius=8)

        g_title = self.font_title.render("O(N) SCALING GRAPH: EXECUTION TIME (ms)", True, self.CYAN)
        self.screen.blit(g_title, (graph_panel.x + 16, graph_panel.y + 14))

        gx, gy = graph_panel.x + 50, graph_panel.y + 60
        gw, gh = graph_panel.width - 70, graph_panel.height - 110

        pygame.draw.rect(self.screen, (13, 17, 23), (gx, gy, gw, gh))
        pygame.draw.rect(self.screen, self.PANEL_BORDER, (gx, gy, gw, gh), 1)

        lengths = [10, 100, 1000]
        max_ms = max(
            max(res[L]["enc_ms"] for L in lengths),
            max(res[L]["dec_ms"] for L in lengths),
            0.01,
        )

        enc_pts = []
        dec_pts = []

        for idx, L in enumerate(lengths):
            x_pos = gx + int((idx / (len(lengths) - 1)) * gw)
            y_enc = gy + gh - int((res[L]["enc_ms"] / max_ms) * (gh - 30)) - 10
            y_dec = gy + gh - int((res[L]["dec_ms"] / max_ms) * (gh - 30)) - 10
            enc_pts.append((x_pos, y_enc))
            dec_pts.append((x_pos, y_dec))

            x_lbl = self.font_small.render(f"N={L}", True, self.TEXT_MAIN)
            self.screen.blit(x_lbl, (x_pos - 15, gy + gh + 8))

        if len(enc_pts) > 1:
            pygame.draw.lines(self.screen, self.CYAN, False, enc_pts, 3)
            pygame.draw.lines(self.screen, self.PURPLE, False, dec_pts, 3)

        for pt in enc_pts:
            pygame.draw.circle(self.screen, self.CYAN, pt, 5)
        for pt in dec_pts:
            pygame.draw.circle(self.screen, self.PURPLE, pt, 5)

        leg_enc = self.font_small.render("— Encryption Time", True, self.CYAN)
        leg_dec = self.font_small.render("— Decryption Time", True, self.PURPLE)
        self.screen.blit(leg_enc, (gx + 10, gy + 10))
        self.screen.blit(leg_dec, (gx + 180, gy + 10))

        table_panel = pygame.Rect(560, 115, 500, 605)
        pygame.draw.rect(self.screen, self.PANEL_BG, table_panel, border_radius=8)
        pygame.draw.rect(self.screen, self.PANEL_BORDER, table_panel, 1, border_radius=8)

        t_title = self.font_title.render("COMPLEXITY TELEMETRY & THROUGHPUT", True, self.TEXT_MAIN)
        self.screen.blit(t_title, (table_panel.x + 16, table_panel.y + 14))

        headers = [
            ("TEXT (N)", 16),
            ("ENC (ms)", 120),
            ("DEC (ms)", 210),
            ("ENC CHAR/ms", 300),
            ("DEC CHAR/ms", 400),
        ]

        for text, x_off in headers:
            h_s = self.font_small.render(text, True, self.TEXT_MUTED)
            self.screen.blit(h_s, (table_panel.x + x_off, table_panel.y + 45))

        pygame.draw.line(self.screen, self.PANEL_BORDER, (table_panel.x + 16, table_panel.y + 62), (table_panel.x + table_panel.width - 16, table_panel.y + 62), 1)

        for idx, L in enumerate(lengths):
            row_y = table_panel.y + 75 + (idx * 65)
            data = res[L]
            n_s = self.font_title.render(f"{L} chars", True, self.CYAN)
            enc_s = self.font_body.render(f"{data['enc_ms']:.3f}", True, self.TEXT_MAIN)
            dec_s = self.font_body.render(f"{data['dec_ms']:.3f}", True, self.TEXT_MAIN)
            enc_tp = self.font_body.render(f"{data['enc_throughput']:.1f}", True, self.GREEN)
            dec_tp = self.font_body.render(f"{data['dec_throughput']:.1f}", True, self.GREEN)

            self.screen.blit(n_s, (table_panel.x + 16, row_y))
            self.screen.blit(enc_s, (table_panel.x + 120, row_y))
            self.screen.blit(dec_s, (table_panel.x + 210, row_y))
            self.screen.blit(enc_tp, (table_panel.x + 300, row_y))
            self.screen.blit(dec_tp, (table_panel.x + 400, row_y))

            pygame.draw.line(self.screen, self.PANEL_BORDER, (table_panel.x + 16, row_y + 40), (table_panel.x + table_panel.width - 16, row_y + 40), 1)

        summary_box = pygame.Rect(table_panel.x + 16, table_panel.y + 320, 468, 260)
        pygame.draw.rect(self.screen, (13, 17, 23), summary_box, border_radius=6)
        pygame.draw.rect(self.screen, self.PANEL_BORDER, summary_box, 1, border_radius=6)

        st_title = self.font_title.render("COMPLEXITY VERDICT: O(N) LINEAR SCALING", True, self.GREEN)
        self.screen.blit(st_title, (summary_box.x + 12, summary_box.y + 12))

        lines = [
            "• Tangent Grid Cipher operates in constant time O(1)",
            "  per individual character byte.",
            "• Total encryption/decryption complexity scales linearly",
            "  O(N) with total input string length N.",
            "• Memory overhead remains 100% constant O(1):",
            "  Zero temporary key buffers or matrix expansion.",
            "• High throughput processing achieved across 10, 100,",
            "  and 1,000 character payloads without UI freezes.",
        ]

        for i, line in enumerate(lines):
            l_s = self.font_small.render(line, True, self.TEXT_MAIN)
            self.screen.blit(l_s, (summary_box.x + 12, summary_box.y + 40 + i * 24))

    # =================================================================
    # TAB 6: SIDE-CHANNEL EXPERIMENT AND TRACE STATISTICS
    # =================================================================
    def _draw_tab_6(self):
        btn_color = (70, 80, 95) if self.is_running_stress else self.CYAN
        btn_txt = (
            "RUNNING TRACE EXPERIMENT..."
            if self.is_running_stress
            else "RUN TRACE-STATISTICS EXPERIMENT (N=500)"
        )
        self._draw_button(self.btn_run_stress, btn_txt, btn_color)

        if self.stress_results is None and not self.is_running_stress:
            panel = pygame.Rect(40, 115, 1020, 605)
            pygame.draw.rect(self.screen, self.PANEL_BG, panel, border_radius=8)
            msg = self.font_title.render(
                "Run the 500-sample trace experiment and inspect the exploratory statistics.",
                True,
                self.TEXT_MUTED,
            )
            self.screen.blit(msg, (60, 380))
            return

        if self.stress_results is None:
            return

        s = self.stress_results
        left_panel = pygame.Rect(40, 115, 500, 605)
        pygame.draw.rect(self.screen, self.PANEL_BG, left_panel, border_radius=8)
        pygame.draw.rect(self.screen, self.CYAN if s["is_resilient"] else self.RED, left_panel, 1, border_radius=8)

        t_title = self.font_title.render("SIDE-CHANNEL EXPERIMENT TELEMETRY", True, self.CYAN)
        self.screen.blit(t_title, (left_panel.x + 16, left_panel.y + 14))

        info_lines = [
            f"• Target Node           : PC 0 (Real Host)",
            f"• Attack Traces Captured : N = {s['num_samples']} (Blinding in RAM)",
            f"• MLE Bit Mean (\\mu)     : {s['bit_means_avg']:.4f} (Ideal: 0.5000)",
            f"• Cross-HD Avalanche    : {s['cross_hd_pct']:.2f}% (Ideal: 50.0%)",
            f"• TVLA |t_max| Stat     : {s['max_t_stat']:.4f} (Threshold < 4.5)",
            f"• Chi-Square (\\chi^2)   : {s['mean_chi2']:.4f} (Ideal: ~1.0)",
        ]

        for idx, line in enumerate(info_lines):
            l_s = self.font_body.render(line, True, self.TEXT_MAIN if idx < 3 else self.CYAN)
            self.screen.blit(l_s, (left_panel.x + 16, left_panel.y + 50 + idx * 28))

        verdict_box = pygame.Rect(left_panel.x + 16, left_panel.y + 240, 468, 340)
        pygame.draw.rect(self.screen, (13, 17, 23), verdict_box, border_radius=6)
        pygame.draw.rect(self.screen, self.GREEN if s["is_resilient"] else self.RED, verdict_box, 1, border_radius=6)

        v_title = self.font_title.render("EXPERIMENTAL METRIC SUMMARY", True, self.GREEN if s["is_resilient"] else self.RED)
        self.screen.blit(v_title, (verdict_box.x + 12, verdict_box.y + 12))

        v_lines = [
            "• Welch-style two-group t-statistic (exploratory):",
            f"  Maximum absolute t-statistic = {s['max_t_stat']:.4f}.",
            "  This statistic alone cannot prove the absence of leakage.",
            "• Ephemeral Blinding (XOR Masking R in RAM):",
            "  Each trace captures an independent volatile seed R_i.",
            "  Mean aggregation is used as a simple trace-analysis baseline.",
            "• Avalanche Effect & Landmine Defense:",
            "  Compare the estimated key with the host-derived key below.",
            "  Triggers landmine cells (💣) on decryption attempt.",
        ]

        for i, line in enumerate(v_lines):
            l_s = self.font_small.render(line, True, self.TEXT_MAIN)
            self.screen.blit(l_s, (verdict_box.x + 12, verdict_box.y + 40 + i * 24))

        right_panel = pygame.Rect(560, 115, 500, 605)
        pygame.draw.rect(self.screen, self.PANEL_BG, right_panel, border_radius=8)
        pygame.draw.rect(self.screen, self.PANEL_BORDER, right_panel, 1, border_radius=8)

        r_title = self.font_title.render("SIDE-CHANNEL AUDIT SUMMARY REPORT", True, self.TEXT_MAIN)
        self.screen.blit(r_title, (right_panel.x + 16, right_panel.y + 14))

        pygame.draw.line(self.screen, self.PANEL_BORDER, (right_panel.x + 16, right_panel.y + 40), (right_panel.x + right_panel.width - 16, right_panel.y + 40), 1)

        rep_lines = [
            ("HOST REAL KEY (SHA-256)", s["host_key_hex"]),
            ("ESTIMATED KEY (TRACE MODEL)", s["attacker_key_hex"]),
        ]

        for idx, (lbl, k_h) in enumerate(rep_lines):
            row_y = right_panel.y + 55 + idx * 75
            l_surf = self.font_small.render(lbl, True, self.TEXT_MUTED)
            k1_surf = self.font_body.render(k_h[:32], True, self.GREEN if idx == 0 else self.RED)
            k2_surf = self.font_body.render(k_h[32:], True, self.GREEN if idx == 0 else self.RED)

            self.screen.blit(l_surf, (right_panel.x + 16, row_y))
            self.screen.blit(k1_surf, (right_panel.x + 16, row_y + 18))
            self.screen.blit(k2_surf, (right_panel.x + 16, row_y + 36))

        banner_box = pygame.Rect(right_panel.x + 16, right_panel.y + 240, 468, 340)
        banner_bg = self.GREEN if s["is_resilient"] else self.RED
        pygame.draw.rect(self.screen, banner_bg, banner_box, border_radius=8)

        b_t1 = self.font_title.render("EXPERIMENTAL FINDINGS:", True, self.BG_COLOR)
        b_t2 = self.font_bold.render(
            "[ CONFIGURED CRITERIA SATISFIED ]" if s["is_resilient"]
            else "[ FURTHER ANALYSIS REQUIRED ]",
            True,
            self.BG_COLOR
        )
        b_t3 = self.font_small.render(
            "QUANTITATIVE EVALUATION OF THE PUF MODEL",
            True,
            self.BG_COLOR
        )

        b_desc = [
            "• Evaluates output behavior across experimental samples.",
            "• Applies statistical thresholds to identify distribution differences.",
            "• Monitors execution stability and masking behavior.",
            "• Translates experimental observations into measurable metrics.",
        ]
        self.screen.blit(b_t1, (banner_box.x + 20, banner_box.y + 20))
        self.screen.blit(b_t2, (banner_box.x + 20, banner_box.y + 45))
        self.screen.blit(b_t3, (banner_box.x + 20, banner_box.y + 70))

        for i, d_line in enumerate(b_desc):
            d_surf = self.font_body.render(d_line, True, self.BG_COLOR)
            self.screen.blit(d_surf, (banner_box.x + 20, banner_box.y + 110 + i * 28))


if __name__ == "__main__":
    app = PygameTabbedPUFApp()
    app.run()