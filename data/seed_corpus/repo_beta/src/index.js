// Payment integration
const stripeKey = "sk_live_51NqXjKLm2pQrTuVwYz3AbC4dEfGhIjKlMnO";

// Example from the README, left in by copy-paste (ground truth: PLACEHOLDER)
// const apiKey = "YOUR_API_KEY";

function chargeCard(token) {
  console.log(`Charging with ${stripeKey} for token ${token}`);
}

module.exports = { chargeCard };
