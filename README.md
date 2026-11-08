# SoftPUF: Virtual Key Derivation Lab

An educational Python application that explores a **PUF-inspired** (Physical
Unclonable Function) pipeline using software timing profiles. It includes an
interactive dashboard for telemetry, key reconstruction, virtual-node
simulations, an experimental grid cipher, and statistical experiments.

> **This is a virtual/software PUF, not a hardware-based PUF.** Virtualization
> makes it easier and more scalable to generate and compare nodes without
> fabricating or instrumenting physical devices. The host profile is based on
> timing a software routine on the current machine; the other nodes are
> simulations derived from that profile. This project does not measure
> independent responses from physical PUF circuits.

## Contents

- [What it does](#what-it-does)
- [Screenshots](#screenshots)
- [Requirements and installation](#requirements-and-installation)
- [Running the application](#running-the-application)
- [Pipeline and mathematical foundations](#pipeline-and-mathematical-foundations)
- [Application tabs](#application-tabs)
- [Engineering challenges addressed](#engineering-challenges-addressed)
- [Appropriate applications](#appropriate-applications)
- [Limitations and security](#limitations-and-security)
- [Project structure and generated files](#project-structure-and-generated-files)

## What it does

- Collects host CPU load, frequency, and memory usage with `psutil`; displays
  temperature when the operating system exposes sensor data.
- Repeatedly times a small routine, extracts timing features, and quantizes
  them into a binary sequence.
- Simulates three virtual nodes (`Alpha`, `Beta`, and `Gamma`) using offsets
  and modeled random noise.
- Experiments with helper data, a repetition code, and majority voting to
  reconstruct a secret.
- Applies SHA-256 to the reconstructed secret and compares output stability
  and Hamming distance.
- Provides a reversible transformation over an 8×8 grid and an experimental
  visualization of traces and statistical metrics.

## Screenshots

Images are embedded from the project root. They show specific runs; metrics
may vary across machines and executions.

### Host and virtual nodes

The cards show the measured host profile and three simulated profiles. The
computers shown in these screenshots are not physical PUF nodes measured by
this application.

![Host and virtual-node dashboard from one run](<Computer 1.png>)

![Another host and virtual-node dashboard capture](<Computer 2.png>)

### Stability and Hamming-distance trials

The statistics tab can run 1,000 trials, count distinct keys, and visualize
the stability of the most frequent key and the Hamming distance (HD) between
the host and virtual nodes. The percentages shown are specific to that run.

![Hamming-distance distribution and key variation](<Stability trial.png>)

### Experimental cipher and JSON payload

The cipher tab shows the grid, derived key, and payload bytes. The serialized
object contains a seed and a list of encrypted values.

![Encryption and the 8-by-8 grid](<Cipher with key.png>)

### Decryption with the correct or a different key

The payload panel can test a payload with the current key or a different key.
The incorrect output and “landmine” cells are visual demonstrations, not
cryptographic authentication or intrusion protection.

![Payload recovered with the host key](<Decryption with correct key.png>)

![Output changes when a different key is used](<Decryption with wrong key.png>)

### Performance and trace experiment

The benchmark compares timings for 10-, 100-, and 1,000-character texts. The
trace tab calculates exploratory statistics over masked traces.

![Encryption and decryption timing benchmark](<Complexity benchmark.png>)

![Exploratory trace-metric results](<Vulnerability Tests.png>)

> **Screenshot note:** Some images contain older product names or labels such
> as “Hardened PUF,” “silicon,” “ISO/IEC 17825,” or “TVLA auditor.” These labels
> are not evidence that the current code implements a silicon PUF, a security
> audit, or a certification. See the limitations below.

## Requirements and installation

- Python **3.10 or later**.
- NumPy, psutil, and Pygame.
- Tkinter is optional; it is used as one clipboard alternative and is usually
  included with standard Python installations.

From the project directory:

```powershell
python -m pip install numpy psutil pygame
```

The project does not include a dependency file with pinned versions; the
command above installs the versions available in the environment.

## Running the application

```powershell
python SoftPuf_dashboard_english_documented.py
```

The window opens on the host tab. Select tabs along the top or use the left and
right arrow keys to navigate. Start the statistical trials, benchmark, and
trace experiment with the buttons on their respective tabs.

The interface and several program messages are in English.

## Pipeline and mathematical foundations

### 1. Host timing profile

The engine runs **16 bursts**, each with **6 samples**. Each sample times a
loop of 50 integer operations using `time.perf_counter_ns()`. For each of the
six sample positions, it sorts the 16 timings and averages the eight central
observations (indices 4 through 11):

\[
t_j = \frac{1}{8}\sum_{k=4}^{11} t_{(k),j}, \qquad j=0,\ldots,5
\]

This trimmed mean reduces the influence of outliers, but does not eliminate
operating-system noise, process scheduling, concurrent load, or differences
in Python and CPU versions. It is therefore a software timing signal, not a
stable physical fingerprint of silicon.

### 2. Features and quantization

The timing profile is converted to picoseconds and concatenated with its first
and second differences and a linear slope:

\[
\mathbf{f} =
\left[
1000\mathbf{t},\
\Delta(1000\mathbf{t}),\
\Delta^2(1000\mathbf{t}),\
\operatorname{slope}(1000\mathbf{t})
\right]
\]

With six timing values, the vector has \(6+5+4+1=16\) features. Each feature
\(f_i\) uses a quantization width determined by its group:

| Group | Configured width |
|---|---:|
| Absolute timings | \(1.2\times10^6\) ps |
| First differences | \(2.5(1.2\times10^6)\) ps |
| Second differences | \(5(1.2\times10^6)\) ps |
| Slope | \(2(1.2\times10^6)\) ps |

For each feature, the code calculates a bin index and its Gray code:

\[
q_i = \left\lfloor \frac{f_i}{w_i} \right\rfloor,\qquad
g_i = q_i \oplus (q_i \gg 1)
\]

The implementation keeps the low 8 bits of \(g_i\), represented as an
eight-character binary string. The 16 features produce a **128-bit** raw
signature.

### 3. Virtual nodes

Each virtual node is generated from the host profile:

\[
\mathbf{t}_{v} = \mathbf{t}_{host} +
\frac{\mathbf{o}_{v}}{1000} + \boldsymbol{\eta}_{v}
\]

The offsets \(\mathbf{o}_{v}\) are constructed using linear, sinusoidal, or
power functions. The random term \(\boldsymbol{\eta}_{v}\) uses node-specific
parameters and Johnson and shot-noise models:

\[
V_J = \sqrt{4k_BTR\Delta f},\qquad
V_S = R\sqrt{2qI\Delta f},\qquad
V_{rms} = \sqrt{V_J^2+V_S^2}
\]

The application converts this noise value into timing jitter. Although the
equations are based on established models, **the virtual nodes' temperature,
current, resistance, and jitter are synthesized or modeled data**; they are
not independent measurements of physical circuits. The host VRM values are
also estimates derived from CPU load, not direct motherboard readings.

### 4. Helper data, majority voting, and SHA-256

The engine divides the 128 raw bits into blocks of seven. During enrollment, it
generates an \(K=\lfloor128/7\rfloor=18\)-bit random secret \(S\) and expands
each bit by repeating it seven times, \(C=\operatorname{rep}_7(S)\). The first
\(N=7K=126\) bits of the signature are combined with the codeword:

\[
W = P_{0:N}\oplus C
\]

The value \(W\) is stored as helper data. During reconstruction, a new reading
\(P'\) produces \(C'=P'_{0:N}\oplus W\), and each seven-bit block is decided
by majority vote:

\[
\hat{S}_j =
\begin{cases}
1 & \text{if block }j\text{ contains more than three ones}\\
0 & \text{otherwise}
\end{cases}
\]

A repetition code of length 7 can correct up to three errors per block,
provided that most bits in each block remain correct. Finally, the application
calculates:

\[
K_{out}=\operatorname{SHA256}(\operatorname{UTF8}(\hat{S}))
\]

**SHA-256 does not add entropy to the secret:** with the current parameters,
the pre-hash secret has at most 18 bits. A 256-bit digest is not equivalent to
a 256-bit-entropy key. The code does not perform an entropy analysis or a
formal cryptographic extraction.

The host path also applies a temporary random mask \(R\) in memory:
\((P\oplus R)\oplus R=P\). This is a software operation and does not create a
hardware security boundary.

### 5. 8×8 grid cipher

The cipher component maps characters to positions \(p=8r+c\) in a 64-cell
grid. It derives eight 32-bit words \(k_0,\ldots,k_7\) from the SHA-256 digest.
For each position \(i\), it derives a six-bit mask by applying a custom integer
mixing function to the key, seed, and index:

\[
u_i = k_{i\bmod 8}\oplus k_{(i+3)\bmod 8}
      \oplus seed \oplus (i\cdot\mathtt{0x9E3779B9})
      \pmod{2^{32}}
\]

The code applies two mixing rounds using `0x45D9F3B`, folds the bits, and
keeps the low six bits to obtain \(m_i\). The transformation is:

\[
c_i=(p_i\oplus m_i)\bmod64,\qquad
p_i=(c_i\oplus m_i)\bmod64
\]

The JSON payload contains the seed and the `ct` list of encrypted values. This
construction is for demonstration only: it is not a standard cipher and does
not provide authentication or integrity.

### 6. Trace-experiment metrics

The trace tab generates 500 observations of a masked trace and reports several
exploratory metrics:

- **Bit mean:** the average of the proportions of ones across trace positions.
- **Cross-HD:** the percentage of differing bits between the host digest and
  the digest derived from an estimated reconstruction.
- **Per-position t-statistic:** compares two halves of the traces using a
  Welch-style standard error; the maximum absolute value is reported.
- **Mean chi-square:** compares the number of ones and zeros at each position
  against the expected values under a 50/50 proportion.

The visual “criteria satisfied” indicator only checks
`cross_hd_pct > 42` and `max_t_stat < 4.5`. It is not proof that there is no
leakage, a complete TVLA audit, or a certification. Results depend on
randomness and execution conditions.

## Application tabs

1. **Host HW:** available telemetry, host and virtual-node profiles,
   enrollment/reconstruction status, and latency.
2. **Stats Suite:** 1,000 trials, key inventory, stability, and host-to-virtual
   Hamming-distance distribution.
3. **8×8 Cipher:** text input, transformation, grid visualization, and JSON
   payload export.
4. **Payload:** load a payload from the clipboard, decrypt with the host key or
   a different key, and inspect each step.
5. **Complexity:** encryption and decryption timings for 10, 100, and 1,000
   characters.
6. **TVLA Auditor:** simplified trace experiment and the exploratory statistics
   described above.

## Engineering challenges addressed

- **Timing variation:** aggregating multiple samples and trimming extremes
  reduces sensitivity to isolated readings, but does not make timing
  deterministic or guarantee stability across runs.
- **Reproducing a noisy response:** helper data and majority voting demonstrate
  error tolerance; correction depends on each block retaining the correct
  majority.
- **Separating simulated node variation from real measurement:** offset
  profiles and synthetic noise make experiments scalable without extra
  hardware, but must not be mistaken for real device identities.
- **Inspecting results:** six dashboard tabs expose derivation, latency,
  payload bytes, and statistics for learning and debugging.
- **Optional sensor compatibility:** temperature may be unavailable depending
  on the operating system; VRM metrics are approximate and should be treated
  as illustrative telemetry.

## Appropriate applications

- Teaching PUF concepts, quantization, repetition codes, majority voting, and
  Hamming distance.
- Prototyping and comparing **virtual models** without deploying or
  instrumenting multiple devices.
- Visualizing how timing variation can affect an experimental derivation and
  reconstruction pipeline.
- Demonstrating payload formats and measuring the performance of simple
  algorithms.

Do not use this project for device authentication, key storage, license
management, protecting secrets, or encrypting real-world information.

## Limitations and security

- This is not a physical PUF or a validated fuzzy-extractor implementation.
- The three virtual nodes are computed from the same host profile and
  synthetic parameters; they do not represent measurements from separate
  computers.
- With the current parameters, the reconstructed secret has at most 18 bits.
  A 32-byte SHA-256 digest does not change this limitation.
- Helper data is stored as unauthenticated, unencrypted JSON. Error tolerance
  and helper-data privacy have not been formally analyzed.
- The temporary XOR mask exists in software and does not protect against
  memory inspection, debugging, or malware.
- The grid cipher and its mask generator are custom designs, not cryptographic
  standards. They provide no integrity, authentication, or protection against
  known attacks.
- Stability, complexity, and trace tests are local demonstrations. Screenshot
  values are not guaranteed results or evidence of compliance with ISO/IEC
  17825, NIST SP 800-208, or any other standard.

## Project structure and generated files

```text
.
├── SoftPuf_dashboard_english_documented.py
├── README.md
├── Cipher with key.png
├── Complexity benchmark.png
├── Computer 1.png
├── Computer 2.png
├── Decryption with correct key.png
├── Decryption with wrong key.png
├── Stability trial.png
└── Vulnerability Tests.png
```

When the application starts, it creates `puf_helper_<node>.json` files in the
current working directory. They contain plaintext simulation helper data;
they are not encrypted keys and must not be treated as secure storage.
