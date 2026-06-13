// Safe data access: static $where and typed operators, relative redirects.
// A scanner that flags any of these is producing a false positive.
const express = require("express");
const router = express.Router();

function activeAllocations(db) {
    // Constant $where string — inefficient maybe, but not injection.
    return db.collection("allocations").find({ $where: "this.active == true" });
}

function searchAllocations(db, userId, threshold) {
    // Typed query operators, no $where, no interpolation into a query string.
    return db.collection("allocations").find({ userId: userId, stocks: { $gt: threshold } });
}

router.get("/home", (req, res) => {
    res.redirect("/dashboard"); // static, relative target
});

module.exports = { router, activeAllocations, searchAllocations };
