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


## Motivation & Human-Centric Threat Model


This project grew from a human-security question: how might local community
journalists and human-rights reporters working in high-risk conflict zones,
including rural Colombia, protect sensitive reporting if a device is seized
or they face physical coercion? Standard disk encryption and stored key files
can leave recognizable forensic artifacts. Even when AES-256 protects the
contents, finding an encrypted volume or key file can expose its possessor to
coercion simply for having hidden material.


The prototype explores two research hypotheses, not established security
claims:


1. **Zero-key storage in user-space:** Can an off-the-shelf laptop derive a
   reproducible, device-bound key from runtime execution timing in user-space
   Python, without storing the key persistently or requiring specialized
   silicon such as an FPGA or TPM?
2. **Failure under cross-machine cloning:** If encrypted payloads are copied
   to another computer, can microarchitectural timing divergence make key
   reconstruction fail?


The present implementation does not establish either hypothesis as a secure
deployment property. It saves unencrypted helper data, has very limited
pre-hash entropy, and does not implement a standard authenticated cipher. See
[Limitations and security](#limitations-and-security).


## Contents


- [What it does](#what-it-does)
- [Motivation & Human-Centric Threat Model](#motivation--human-centric-threat-model)
- [Screenshots](#screenshots)
- [Requirements and installation](#requirements-and-installation)
- [Running the application](#running-the-application)
- [Pipeline and mathematical foundations](#pipeline-and-mathematical-foundations)
- [Empirical Findings](#empirical-findings)
- [Field Deployment Roadmap](#field-deployment-roadmap)
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


In both screenshots, `PC 0 (Real Host)` is the software timing pipeline
genuinely measured on a physical computer. The remaining nodes, `Alpha`,
`Beta`, and `Gamma`, are software simulations derived from that host profile;
they are not independently measured devices or physical PUF circuits.


**Computer 1 — HP ENVY Laptop:** 13th Gen Intel Core i7-13700H, Windows 11,
and 64 GB RAM. This host run produced a raw signature and SHA-256 digest
beginning `1508700c...`.


![Computer 1: HP ENVY physical host and simulated virtual nodes](<Computer 1.png>)


**Computer 2 — Gigabyte Desktop:** Intel Core i9-9900K, Windows 10, and
16 GB RAM.


Across these two distinct microarchitectures, the host pipeline produced
completely different raw signatures and SHA-256 digests (`1508700c...` vs
`d6384d76...`). These are observations from two runs, not a general guarantee
of device uniqueness or cross-machine security.


![Computer 2: Gigabyte physical host and simulated virtual nodes](<Computer 2.png>)


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
> are legacy prototype labels, not evidence that the current code implements
> a silicon PUF, a formal security audit, or hardware certification. See the
> limitations below.


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


$$
t_j = \frac{1}{8}\sum_{k=4}^{11} t_{(k),j}, \qquad j=0,\ldots,5
$$


This trimmed mean reduces the influence of outliers, but does not eliminate
operating-system noise, process scheduling, concurrent load, or differences
in Python and CPU versions. It is therefore a software timing signal, not a
stable physical fingerprint of silicon.


### 2. Features, finite differences, and quantization


The timing profile is converted to picoseconds and concatenated with its first
and second differences and a linear slope:


$$
\mathbf{f} =
\left[
1000\mathbf{t},\
\Delta(1000\mathbf{t}),\
\Delta^2(1000\mathbf{t}),\
\mathrm{slope}(1000\mathbf{t})
\right]
$$


With six timing values, the vector has $6+5+4+1=16$ features. Each feature
$f_i$ uses a quantization width determined by its group:


| Group | Configured width |
|---|---:|
| Absolute timings | 1.2106 ps |
| First differences | 2.5(1.2106) ps |
| Second differences | 5.0(1.2106) ps |
| Slope | 2.0(1.2106) ps |


For each feature, the code calculates a bin index and its Gray code:


$$
q_i = \left\lfloor \frac{f_i}{w_i} \right\rfloor,\qquad
g_i = q_i \oplus (q_i \gg 1)
$$


The implementation keeps the low 8 bits of $g_i$, represented as an
eight-character binary string. The 16 features produce a **128-bit** raw
signature.


#### Why first and second differences?


User-space timings $\mathbf{t}$ can shift with additive thermal or system-load
offsets and can drift with a linear frequency-scaling ramp. First differences
reject a uniform additive offset; second differences reject a linear ramp. For
$t'_j=t_j+\delta$, and more generally
$t'_j=t_j+\alpha j+\delta$, the transforms behave as follows:


$$
\Delta t'_j = \Delta t_j + \alpha,\qquad
\Delta^2 t'_j = \Delta^2 t_j
$$


Thus $\Delta t_j=t_{j+1}-t_j$ removes $\delta$, while
$\Delta^2t_j=t_{j+2}-2t_{j+1}+t_j$ removes both $\delta$ and the ramp
$\alpha j$. The second differences emphasize local non-linear changes in the
measured profile; they do not prove that these changes are unique to a device
or secret.


Differencing also amplifies independent measurement noise. Under the
simplified model that profile elements have independent Gaussian noise of
variance $\sigma^2$, then:


$$
\mathrm{Var}(\Delta t)=2\sigma^2,\qquad
\mathrm{Var}(\Delta^2t)=(1^2+(-2)^2+1^2)\sigma^2=6\sigma^2
$$


The implementation uses a three-stage mitigation cascade in
`AdvancedPUFEngine`:


1. **Trimmed-mean pre-filtering:** For each of six sample positions, it
   averages only the eight central observations from 16 bursts
   (`sorted_matrix[4:12]`), reducing the impact of extreme scheduler
   interruptions before differentiation.
2. **Variance-scaled adaptive quantization:** The implementation uses
   preset group-scaled bin widths motivated by the variance growth (not a
   runtime variance estimate):
   $1.0\times$ for $\mathbf{t}$, $2.5\times$ for $\Delta\mathbf{t}$, and
   $5.0\times$ for $\Delta^2\mathbf{t}$. The second-difference width exceeds
   the $\sqrt{6}\approx2.45$ standard-deviation growth under the independent,
   equal-variance noise model.
3. **Gray coding and repetition error correction:** Each bin index is Gray
   encoded, $g_i=q_i\oplus(q_i\gg1)$, so adjacent bins differ by at most one
   encoded bit. An isolated adjacent-bin flip is within the length-7
   repetition code's (`ecc_rep = 7`) correction capacity: majority vote
   corrects up to three bit errors per block, provided no more than three
   bits in that block are wrong.


**Entropy caveat:** $\Delta\mathbf{t}$ and $\Delta^2\mathbf{t}$ are
deterministic linear transformations of $\mathbf{t}$. They can improve
environmental invariance and bit stability, but do not add independent
Shannon entropy if an adversary already knows $\mathbf{t}$.


### 3. Virtual nodes


Each virtual node is generated from the host profile:


$$
\mathbf{t}_{v} = \mathbf{t}_{host} +
\frac{\mathbf{o}_{v}}{1000} + \boldsymbol{\eta}_{v}
$$


The offsets $\mathbf{o}_{v}$ are constructed using linear, sinusoidal, or
power functions. The random term $\boldsymbol{\eta}_{v}$ uses node-specific
parameters and Johnson and shot-noise models:


$$
V_J = \sqrt{4k_BTR\Delta f},\qquad
V_S = R\sqrt{2qI\Delta f},\qquad
V_{rms} = \sqrt{V_J^2+V_S^2}
$$


The application converts this noise value into timing jitter. Although the
equations are based on established models, **the virtual nodes' temperature,
current, resistance, and jitter are synthesized or modeled data**; they are
not independent measurements of physical circuits. The host VRM values are
also estimates derived from CPU load, not direct motherboard readings.


### 4. Helper data, majority voting, and SHA-256


The engine divides the 128 raw bits into blocks of seven. During enrollment, it
generates a $K=\lfloor128/7\rfloor=18$-bit random secret $S$ and expands
each bit by repeating it seven times, $C=\mathrm{rep}_7(S)$. The first
$N=7K=126$ bits of the signature are combined with the codeword:


$$
W = P_{0:N}\oplus C
$$


The value $W$ is stored as helper data. During reconstruction, a new reading
$P'$ produces $C'=P'_{0:N}\oplus W$, and each seven-bit block is decided
by majority vote:


$$
\hat{S}_j =
\begin{cases}
1 & \text{if block }j\text{ contains more than three ones}\\
0 & \text{otherwise}
\end{cases}
$$


A repetition code of length 7 can correct up to three errors per block,
provided that most bits in each block remain correct. Finally, the application
calculates:


$$
K_{out}=\mathrm{SHA256}(\mathrm{UTF8}(\hat{S}))
$$


**SHA-256 does not add entropy to the secret:** with the current parameters,
the pre-hash secret has at most 18 bits. A 256-bit digest is not equivalent to
a 256-bit-entropy key. The code does not perform an entropy analysis or a
formal cryptographic extraction.


The host path also applies a temporary random mask $R$ in memory:
$(P\oplus R)\oplus R=P$. This is a software operation and does not create a
hardware security boundary.


### 5. 8×8 grid cipher


The cipher component maps characters to positions $p=8r+c$ in a 64-cell
grid. It derives eight 32-bit words $k_0,\ldots,k_7$ from the SHA-256 digest.
For each position $i$, it derives a six-bit mask by applying a custom integer
mixing function to the key, seed, and index:


$$
u_i = k_{i\bmod 8}\oplus k_{(i+3)\bmod 8}
      \oplus seed \oplus (i\cdot\mathtt{0x9E3779B9})
      \pmod{2^{32}}
$$


The code applies two mixing rounds using `0x45D9F3B`, folds the bits, and
keeps the low six bits to obtain $m_i$. The transformation is:


$$
c_i=(p_i\oplus m_i)\bmod64,\qquad
p_i=(c_i\oplus m_i)\bmod64
$$


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


## Empirical Findings


The following are observations transcribed from the included screenshots,
not independent replications or security guarantees:


- **Primary-key stability:** `Stability trial.png` reports 981 matching
  primary keys in 1,000 trials (**98.1%**) for `PC 0 (Real Host)`. The three
  simulated nodes have mean Hamming distances of **53.43%** (`Alpha`),
  **54.23%** (`Beta`), and **54.58%** (`Gamma`) from the host key, near the
  50% expectation for unrelated bit strings.
- **Grid-transformation runtime:** `Complexity benchmark.png` reports
  **0.010 ms** for 10 characters and **0.630 ms** for 1,000 characters
  (encryption), consistent with linear $O(N)$ work for this implementation
  over the shown input sizes. The screenshot is a single local benchmark, not
  a general performance guarantee.
- **Exploratory trace metrics:** `Vulnerability Tests.png` shows $N=500$
  masked traces, bit mean **0.5008**, Welch-style $|t_{\max}|=2.8847<4.5$,
  and mean $\chi^2=0.8456$. These prototype statistics do not demonstrate
  absence of leakage or satisfy a formal TVLA or certification process.


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


## Field Deployment Roadmap


Moving from this proof of concept to a tool that could responsibly be
evaluated for journalist safety requires substantial independent research,
security review, and field testing. These are engineering goals, not current
capabilities or promises of protection:


1. **Scale entropy and adopt standard authenticated encryption.** Expand
   feature extraction, or evaluate combining user-space timing with
   kernel-level jitter sources, to establish at least 128 bits of measured
   min-entropy under a defensible threat model. Use a reviewed key-derivation
   design and standard **AES-256-GCM** AEAD rather than the experimental 8×8
   grid. Entropy estimates and cross-device/re-enrollment behavior would need
   rigorous validation.
2. **Research plausible deniability through structural steganography.**
   Explore whether compact 126-bit helper data could be represented in
   innocuous personal-document structures, for example in the XML metadata
   or formatting of an ordinary letter to a family member, instead of an
   obvious `puf_helper_<node>.json` file. This is not implemented, and no
   document format can be assumed to conceal data reliably: forensic
   detectability, data loss, and the added risks to a reporter require
   specialist review and testing.
3. **Build an ephemeral, RAM-only stateless relay.** Pair local,
   device-bound derivation with a volatile relay service using a
   dead-man's-switch design: hold session state only in memory and purge it
   automatically or on an authenticated panic trigger. The design goal is no
   intentional persistent server-side session state; logs, backups, crash
   dumps, and infrastructure telemetry would also need explicit controls and
   audits before claiming that confiscation leaves no server-side artifacts.


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



