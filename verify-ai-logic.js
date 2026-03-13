// Verification of the AI Inference Logic Flow
const model1 = "madhurjindal/autonlp-Phishing-Detector-20554160";
const model2 = "elvis/distilbert-phishing-detector";

console.log("Checking AI integration parameters...");
console.log("- Model 1: " + model1);
console.log("- Model 2: " + model2);

const testPayload = "https://paypal-security-update.com";
console.log("Mocking request for: " + testPayload);

// Logic being tested:
const isMalicious = (label) => label.toLowerCase().includes("phish") || label.toLowerCase().includes("malicious") || label === "LABEL_1";

const mockApiResponse = [{ label: "LABEL_1", score: 0.987 }]; // Typical HF response for malicious
console.log("AI Match Logic Test: " + (isMalicious(mockApiResponse[0].label) ? "PASS - Malicious Detected" : "FAIL"));
