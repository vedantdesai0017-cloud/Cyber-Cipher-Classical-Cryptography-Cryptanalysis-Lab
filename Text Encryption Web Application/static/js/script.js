/**
 * Cyber Cipher - Educational Web Application Controller
 * Handles UI interactions, API calls, dynamic algorithm metadata,
 * step-by-step transformation rendering, and attack lab visualizations.
 */

document.addEventListener("DOMContentLoaded", () => {
    // DOM Elements - Workspace
    const cipherSelect = document.getElementById("cipher-select");
    const cipherKey = document.getElementById("cipher-key");
    const keyLabel = document.getElementById("key-label");
    const keyHint = document.getElementById("key-hint");
    const inputText = document.getElementById("input-text");
    const outputText = document.getElementById("output-text");
    const inputCounter = document.getElementById("input-counter");
    const outputCounter = document.getElementById("output-counter");
    const encryptBtn = document.getElementById("encrypt-btn");
    const decryptBtn = document.getElementById("decrypt-btn");
    const swapBtn = document.getElementById("swap-btn");
    const clearWorkspaceBtn = document.getElementById("clear-workspace-btn");
    const copyBtn = document.getElementById("copy-btn");
    const loadSampleBtn = document.getElementById("load-sample-btn");
    const showStepsToggle = document.getElementById("show-steps-toggle");
    const stepsCard = document.getElementById("steps-card");
    const stepsBadge = document.getElementById("steps-badge");
    const stepsSummary = document.getElementById("steps-summary");
    const stepsList = document.getElementById("steps-list");
    const statusBar = document.getElementById("status-bar");
    const toast = document.getElementById("toast");

    // DOM Elements - Info Panel
    const infoType = document.getElementById("info-type");
    const infoName = document.getElementById("info-name");
    const infoHistory = document.getElementById("info-history");
    const infoHow = document.getElementById("info-how");
    const infoKey = document.getElementById("info-key");
    const infoStrengths = document.getElementById("info-strengths");
    const infoWeaknesses = document.getElementById("info-weaknesses");
    const infoExample = document.getElementById("info-example");

    // DOM Elements - Attack Lab
    const tabButtons = document.querySelectorAll(".tab-btn");
    const tabPanels = document.querySelectorAll(".attack-tab-panel");
    const caesarAttackInput = document.getElementById("caesar-attack-input");
    const runCaesarBruteBtn = document.getElementById("run-caesar-brute-btn");
    const caesarBruteResults = document.getElementById("caesar-brute-results");
    const bruteCountBadge = document.getElementById("brute-count");

    const freqInput = document.getElementById("freq-input");
    const runFreqBtn = document.getElementById("run-freq-btn");
    const loadWorkspaceToFreqBtn = document.getElementById("load-workspace-to-freq-btn");
    const freqTotalLettersBadge = document.getElementById("freq-total-letters");
    const freqChartContainer = document.getElementById("freq-chart-container");
    const freqTableBody = document.querySelector("#freq-data-table tbody");
    const freqShowChartBtn = document.getElementById("freq-show-chart");
    const freqShowTableBtn = document.getElementById("freq-show-table");
    const freqTableContainer = document.getElementById("freq-table-container");

    // Algorithm Configuration Dictionary
    const CIPHER_CONFIGS = {
        caesar: {
            name: "Caesar Cipher",
            type: "Monoalphabetic Substitution",
            keyLabel: "Key (Shift)",
            keyPlaceholder: "3",
            defaultValue: "3",
            keyHint: "Numeric integer shift (e.g., 3, 13, or -5)",
            sampleText: "HELLO CYBER CIPHER",
            history: "Named after Julius Caesar, who used it with a shift of 3 to protect military messages around 58 BC.",
            how_it_works: "Each letter in the plaintext is shifted forward or backward by a fixed number of positions in the alphabet (modulo 26). Spaces and punctuation remain unchanged.",
            key_requirements: "A single integer representing the shift amount (can be positive, negative, or greater than 26).",
            strengths: "Extremely simple to understand and implement; computationally lightweight.",
            weaknesses: "Extremely weak. Trivial to break via brute-force (only 25 shifts) or frequency analysis.",
            example: 'Plaintext: "HELLO WORLD", Key: 3 -> Ciphertext: "KHOOR ZRUOG"'
        },
        vigenere: {
            name: "Vigenère Cipher",
            type: "Polyalphabetic Substitution",
            keyLabel: "Key (Keyword)",
            keyPlaceholder: "SECRET",
            defaultValue: "CIPHER",
            keyHint: "Alphabetic keyword (letters only, e.g., SECRET)",
            sampleText: "ATTACK AT DAWN ON THE EASTERN FLANK",
            history: "Misattributed to Blaise de Vigenère, but first described by Giovan Battista Bellaso in 1553. Long considered 'le chiffre indéchiffrable' (the unbreakable cipher).",
            how_it_works: "Uses a repeated keyword to shift plaintext letters by different amounts, cycling through multiple Caesar shifts across the message.",
            key_requirements: "A non-empty alphabetic string. Non-letters in the key are ignored or disallowed.",
            strengths: "Masks single-letter frequency distribution, rendering basic Caesar frequency analysis ineffective.",
            weaknesses: "Vulnerable to Kasiski examination and index of coincidence tests once the keyword length is determined.",
            example: 'Plaintext: "ATTACK", Key: "LEMON" -> Ciphertext: "LXFOPV"'
        },
        rail_fence: {
            name: "Rail Fence Cipher",
            type: "Transposition Cipher",
            keyLabel: "Key (Rails)",
            keyPlaceholder: "3",
            defaultValue: "3",
            keyHint: "Number of rails / rows (integer >= 2)",
            sampleText: "DEFEND THE EAST WALL OF THE CASTLE",
            history: "An ancient transposition technique related to the Greek scytale, used extensively during the American Civil War for field communications.",
            how_it_works: "Plaintext is written diagonally up and down across a zigzag grid of imaginary 'rails', then read off row by row.",
            key_requirements: "An integer >= 2 representing the number of vertical rails.",
            strengths: "Preserves the original letters; obscures letter positions without altering character frequencies.",
            weaknesses: "Vulnerable to anagramming, multiple anagramming attacks, and known-length transposition solving.",
            example: 'Plaintext: "WE ARE DISCOVERED", Rails: 3 -> Ciphertext: "WECRUERDSOEESAV"'
        },
        playfair: {
            name: "Playfair Cipher",
            type: "Polygraphic Substitution",
            keyLabel: "Key (Keyword)",
            keyPlaceholder: "MONARCHY",
            defaultValue: "MONARCHY",
            keyHint: "Alphabetic keyword used to construct the 5x5 matrix",
            sampleText: "HIDE THE GOLD IN THE TREE STUMP",
            history: "Invented by Charles Wheatstone in 1854, but popularized by Lord Playfair. Used by British forces in the Second Boer War and WWI.",
            how_it_works: "Encrypts pairs of letters (digraphs) using a 5x5 key matrix (merging I and J). Digraphs in the same row shift right; same column shift down; opposite corners swap columns.",
            key_requirements: "An alphabetic keyword without symbols. Double letters in pairs are separated by filler 'X'.",
            strengths: "Significantly flatter frequency distribution than monoalphabetic ciphers; 600 possible digraphs instead of 26 letters.",
            weaknesses: "Vulnerable to digraph frequency analysis; reverse-reconstruction of the 5x5 matrix is straightforward with sufficient ciphertext.",
            example: 'Plaintext: "INSTRUMENTS", Key: "MONARCHY" -> Ciphertext: "GATLMZCLRQTX"'
        },
        beaufort: {
            name: "Beaufort Cipher",
            type: "Reciprocal Polyalphabetic Substitution",
            keyLabel: "Key (Keyword)",
            keyPlaceholder: "CIPHER",
            defaultValue: "KEY",
            keyHint: "Alphabetic keyword (letters only)",
            sampleText: "MY SECRET TREASURE IS BURIED AT MIDNIGHT",
            history: "Invented by Sir Francis Beaufort (also famous for the Beaufort wind scale) in 1857.",
            how_it_works: "Similar to Vigenère, but uses the backward subtraction rule: C = (Key - Plaintext) mod 26. Remarkably, encryption and decryption are identical operations (self-reciprocal).",
            key_requirements: "An alphabetic keyword.",
            strengths: "Self-reciprocal: the same mathematical operation encrypts and decrypts, simplifying hardware or field use.",
            weaknesses: "Shares identical cryptographic weaknesses with Vigenère; vulnerable to Kasiski examination and periodic cryptanalysis.",
            example: 'Plaintext: "DEFEND", Key: "KEY" -> Ciphertext: "HBLGZB"'
        },
        autokey: {
            name: "Autokey Cipher",
            type: "Extended Keystream Substitution",
            keyLabel: "Key (Primer Keyword)",
            keyPlaceholder: "QUEEN",
            defaultValue: "QUEEN",
            keyHint: "Initial primer keyword (the plaintext itself then extends the keystream)",
            sampleText: "MEET AT THE SECRET LOCATION TONIGHT",
            history: "Invented by Blaise de Vigenère in 1586 to eliminate the periodic repeating key vulnerability of his predecessor Bellaso.",
            how_it_works: "Begins encrypting with a short primer key, but then appends the plaintext itself to form an extended non-repeating keystream.",
            key_requirements: "An initial alphabetic primer string.",
            strengths: "Eliminates key periodicity; standard Kasiski examination cannot detect repeating key cycles.",
            weaknesses: "Since the keystream consists of meaningful natural language plaintext, cryptanalysts can test high-frequency dictionary words to cascade-recover the text.",
            example: 'Plaintext: "ATTACK AT DAWN", Key: "QUEEN" -> Keystream: "QUEENATTACKAT"'
        }
    };

    // Initialize UI on load
    function init() {
        updateCipherUI();
        updateCounters();
        setupEventListeners();
    }

    // Show Toast Notification
    function showToast(message, type = "success") {
        toast.textContent = message;
        toast.className = `toast show ${type}`;
        setTimeout(() => {
            toast.className = "toast";
        }, 3000);
    }

    // Set Status Message
    function setStatus(message, type = "ready") {
        statusBar.innerHTML = `<span class="status-msg ${type}">${escapeHtml(message)}</span>`;
    }

    // Update Algorithm UI based on selection
    function updateCipherUI() {
        const selected = cipherSelect.value;
        const config = CIPHER_CONFIGS[selected] || CIPHER_CONFIGS.caesar;

        keyLabel.textContent = config.keyLabel;
        cipherKey.placeholder = config.keyPlaceholder;
        cipherKey.value = config.defaultValue;
        keyHint.textContent = config.keyHint;

        infoName.textContent = config.name;
        infoType.textContent = config.type;
        infoHistory.textContent = config.history;
        infoHow.textContent = config.how_it_works;
        infoKey.textContent = config.key_requirements;
        infoStrengths.textContent = config.strengths;
        infoWeaknesses.textContent = config.weaknesses;
        infoExample.textContent = config.example;

        // Reset steps view
        stepsCard.style.display = "none";
        stepsList.innerHTML = "";
        stepsBadge.textContent = "0 steps";
    }

    // Character and Word Counters
    function updateCounters() {
        const inVal = inputText.value;
        const inChars = inVal.length;
        const inWords = inVal.trim() ? inVal.trim().split(/\s+/).length : 0;
        inputCounter.textContent = `${inChars} chars | ${inWords} words`;

        const outVal = outputText.value;
        outputCounter.textContent = `${outVal.length} chars`;
    }

    // HTML Escaping Utility
    function escapeHtml(str) {
        if (!str) return "";
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Render Transformation Steps
    function renderSteps(steps, summary) {
        if (!steps || steps.length === 0) {
            stepsCard.style.display = "none";
            return;
        }

        stepsCard.style.display = "block";
        stepsBadge.textContent = `${steps.length} step${steps.length > 1 ? "s" : ""}`;
        stepsSummary.textContent = summary || "Transformation complete.";
        stepsList.innerHTML = "";

        // Render up to 100 steps to keep UI snappy
        const displayLimit = Math.min(steps.length, 100);
        for (let i = 0; i < displayLimit; i++) {
            const step = steps[i];
            const div = document.createElement("div");
            div.className = "step-item";

            const orig = escapeHtml(step.original || "");
            const trans = escapeHtml(step.transformed || "");
            const detail = escapeHtml(step.detail || "");

            let badgeHtml = "";
            if (step.rule) {
                badgeHtml = `<span class="badge-tag" style="margin-left: 0.5rem; font-size: 0.65rem;">${escapeHtml(step.rule)}</span>`;
            } else if (step.rail) {
                badgeHtml = `<span class="badge-tag" style="margin-left: 0.5rem; font-size: 0.65rem;">Rail ${step.rail}</span>`;
            }

            div.innerHTML = `
                <div class="step-chars">
                    <span class="step-orig">${orig || "&nbsp;"}</span>
                    <span class="step-arr">→</span>
                    <span class="step-trans">${trans || "&nbsp;"}</span>
                    ${badgeHtml}
                </div>
                <div class="step-detail">${detail}</div>
            `;
            stepsList.appendChild(div);
        }

        if (steps.length > 100) {
            const extra = document.createElement("div");
            extra.className = "step-item";
            extra.innerHTML = `<span class="step-detail">... and ${steps.length - 100} additional character steps.</span>`;
            stepsList.appendChild(extra);
        }
    }

    // Execute Encrypt or Decrypt
    async function executeOperation(isEncrypt) {
        const cipher = cipherSelect.value;
        const text = inputText.value;
        const key = cipherKey.value;
        const showSteps = showStepsToggle.checked;

        if (!text || !text.trim()) {
            setStatus("Please enter some text.", "error");
            showToast("Please enter some text.", "error");
            inputText.focus();
            return;
        }

        const endpoint = isEncrypt ? "/encrypt" : "/decrypt";
        const btn = isEncrypt ? encryptBtn : decryptBtn;
        const originalText = btn.innerHTML;

        try {
            btn.disabled = true;
            btn.innerHTML = `<span class="btn-icon">⏳</span> Processing...`;
            setStatus("Executing cryptographic transformation...", "ready");

            const response = await fetch(endpoint, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    cipher: cipher,
                    text: text,
                    key: key,
                    show_steps: showSteps
                })
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                const errMsg = data.error || "Operation failed.";
                setStatus(errMsg, "error");
                showToast(errMsg, "error");
                return;
            }

            outputText.value = data.result;
            updateCounters();
            setStatus(`Successfully ${isEncrypt ? "encrypted" : "decrypted"} message using ${CIPHER_CONFIGS[cipher].name}.`, "success");
            showToast(`${CIPHER_CONFIGS[cipher].name} completed!`, "success");

            if (showSteps && data.steps) {
                renderSteps(data.steps, data.summary);
            } else {
                stepsCard.style.display = "none";
            }
        } catch (err) {
            setStatus("Network error: Failed to reach server.", "error");
            showToast("Server connection error.", "error");
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
    }

    // Attack Lab: Caesar Brute Force Cracker
    async function runCaesarBruteForce() {
        const ciphertext = caesarAttackInput.value;
        if (!ciphertext || !ciphertext.trim()) {
            showToast("Please enter ciphertext to attack.", "error");
            return;
        }

        try {
            runCaesarBruteBtn.disabled = true;
            runCaesarBruteBtn.innerHTML = `<span class="btn-icon">⏳</span> Cracking Keyspace...`;
            bruteCountBadge.textContent = "Cracking...";

            const res = await fetch("/attack/caesar", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ciphertext })
            });

            const data = await res.json();
            if (!res.ok || !data.success) {
                showToast(data.error || "Attack failed.", "error");
                return;
            }

            caesarBruteResults.innerHTML = "";
            bruteCountBadge.textContent = `${data.candidates.length} Shifts Exhausted`;

            data.candidates.forEach((cand) => {
                const item = document.createElement("div");
                item.className = "caesar-candidate-item";

                const shiftLabel = `Shift ${cand.shift}:`;
                const textEscaped = escapeHtml(cand.plaintext);

                item.innerHTML = `
                    <span class="candidate-shift">${shiftLabel}</span>
                    <span class="candidate-text">${textEscaped}</span>
                    <div class="candidate-actions">
                        <button class="btn-mini btn-copy-cand" title="Copy candidate">Copy</button>
                        <button class="btn-mini btn-use-cand" title="Load into Workspace">Use</button>
                    </div>
                `;

                // Candidate Action Listeners
                item.querySelector(".btn-copy-cand").addEventListener("click", () => {
                    navigator.clipboard.writeText(cand.plaintext);
                    showToast(`Copied Shift ${cand.shift} result!`, "success");
                });

                item.querySelector(".btn-use-cand").addEventListener("click", () => {
                    inputText.value = cand.plaintext;
                    cipherSelect.value = "caesar";
                    cipherKey.value = cand.shift.toString();
                    updateCipherUI();
                    updateCounters();
                    showToast(`Shift ${cand.shift} applied to Workspace!`, "success");
                    window.location.hash = "workspace";
                });

                caesarBruteResults.appendChild(item);
            });

            showToast("Exhausted all 25 Caesar shifts successfully!", "success");
        } catch (err) {
            showToast("Error running brute force attack.", "error");
        } finally {
            runCaesarBruteBtn.disabled = false;
            runCaesarBruteBtn.innerHTML = `<span class="btn-icon">⚡</span> Run Brute Force Attack`;
        }
    }

    // Attack Lab: Frequency Analysis
    async function runFrequencyAnalysis() {
        const text = freqInput.value;
        if (!text || !text.trim()) {
            showToast("Please enter text to analyze.", "error");
            return;
        }

        try {
            runFreqBtn.disabled = true;
            runFreqBtn.innerHTML = `<span class="btn-icon">⏳</span> Analyzing...`;

            const res = await fetch("/analysis/frequency", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ text })
            });

            const data = await res.json();
            if (!res.ok || !data.success) {
                showToast(data.error || "Analysis failed.", "error");
                return;
            }

            freqTotalLettersBadge.textContent = `${data.total_letters} Letters Analyzed`;

            // Render Chart Bars
            freqChartContainer.innerHTML = "";
            data.frequencies.forEach((item) => {
                const row = document.createElement("div");
                row.className = "freq-bar-row";

                // Cap max visual bar scale at ~25% for readable chart scaling
                const barWidth = Math.min((item.percentage / 20) * 100, 100);
                const expectedPos = Math.min((item.expected_english / 20) * 100, 100);

                row.innerHTML = `
                    <span class="freq-letter">${item.letter}</span>
                    <div class="bar-track" title="Observed: ${item.percentage}%, English Expected: ${item.expected_english}%">
                        <div class="bar-fill-observed" style="width: ${barWidth}%;"></div>
                        <div class="bar-marker-expected" style="left: ${expectedPos}%;" title="Standard English: ${item.expected_english}%"></div>
                    </div>
                    <div class="freq-stats">
                        <span class="pct">${item.percentage}%</span>
                        <span class="cnt">(${item.count})</span>
                    </div>
                `;
                freqChartContainer.appendChild(row);
            });

            // Render Data Table
            freqTableBody.innerHTML = "";
            data.sorted_frequencies.forEach((item) => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td><strong>${item.letter}</strong></td>
                    <td>${item.count}</td>
                    <td>${item.percentage}%</td>
                    <td>${item.expected_english}%</td>
                `;
                freqTableBody.appendChild(tr);
            });

            showToast("Frequency analysis completed!", "success");
        } catch (err) {
            showToast("Error running frequency analysis.", "error");
        } finally {
            runFreqBtn.disabled = false;
            runFreqBtn.innerHTML = `<span class="btn-icon">📊</span> Analyze Letter Frequencies`;
        }
    }

    // Set up Event Listeners
    function setupEventListeners() {
        // Algorithm Change
        cipherSelect.addEventListener("change", updateCipherUI);

        // Text Counter Updates
        inputText.addEventListener("input", updateCounters);
        outputText.addEventListener("input", updateCounters);

        // Encrypt & Decrypt
        encryptBtn.addEventListener("click", () => executeOperation(true));
        decryptBtn.addEventListener("click", () => executeOperation(false));

        // Swap Text
        swapBtn.addEventListener("click", () => {
            const temp = inputText.value;
            inputText.value = outputText.value;
            outputText.value = temp;
            updateCounters();
            showToast("Input and Output swapped!", "success");
        });

        // Clear Workspace
        clearWorkspaceBtn.addEventListener("click", () => {
            inputText.value = "";
            outputText.value = "";
            stepsCard.style.display = "none";
            stepsList.innerHTML = "";
            updateCounters();
            setStatus("Workspace cleared.", "ready");
            showToast("Workspace cleared.", "success");
        });

        // Copy Result
        copyBtn.addEventListener("click", () => {
            const text = outputText.value;
            if (!text) {
                showToast("No output to copy!", "error");
                return;
            }
            navigator.clipboard.writeText(text).then(() => {
                showToast("Result copied to clipboard!", "success");
            }).catch(() => {
                // Fallback
                outputText.select();
                document.execCommand("copy");
                showToast("Result copied to clipboard!", "success");
            });
        });

        // Load Sample
        loadSampleBtn.addEventListener("click", () => {
            const selected = cipherSelect.value;
            const config = CIPHER_CONFIGS[selected] || CIPHER_CONFIGS.caesar;
            inputText.value = config.sampleText;
            updateCounters();
            showToast(`Loaded sample text for ${config.name}!`, "success");
        });

        // Attack Lab Tabs
        tabButtons.forEach((btn) => {
            btn.addEventListener("click", () => {
                tabButtons.forEach((b) => b.classList.remove("active"));
                tabPanels.forEach((p) => p.classList.remove("active"));

                btn.classList.add("active");
                const targetId = btn.getAttribute("data-tab");
                const panel = document.getElementById(targetId);
                if (panel) panel.classList.add("active");
            });
        });

        // Caesar Brute Force Run
        runCaesarBruteBtn.addEventListener("click", runCaesarBruteForce);

        // Frequency Analysis Run
        runFreqBtn.addEventListener("click", runFrequencyAnalysis);

        // Import Workspace Output to Frequency Analyzer
        loadWorkspaceToFreqBtn.addEventListener("click", () => {
            const text = outputText.value || inputText.value;
            if (!text) {
                showToast("Workspace is currently empty.", "error");
                return;
            }
            freqInput.value = text;
            showToast("Text imported into Frequency Analyzer!", "success");
        });

        // Keyboard Shortcut: Ctrl+Enter (or Cmd+Enter) to Encrypt
        const handleCtrlEnter = (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
                e.preventDefault();
                executeOperation(true);
            }
        };
        inputText.addEventListener("keydown", handleCtrlEnter);
        cipherKey.addEventListener("keydown", handleCtrlEnter);

        // Frequency View Sub-tabs (Chart vs Table)
        freqShowChartBtn.addEventListener("click", () => {
            freqShowChartBtn.classList.add("active");
            freqShowTableBtn.classList.remove("active");
            freqChartContainer.style.display = "flex";
            freqTableContainer.style.display = "none";
        });

        freqShowTableBtn.addEventListener("click", () => {
            freqShowTableBtn.classList.add("active");
            freqShowChartBtn.classList.remove("active");
            freqChartContainer.style.display = "none";
            freqTableContainer.style.display = "block";
        });
    }

    init();
});
