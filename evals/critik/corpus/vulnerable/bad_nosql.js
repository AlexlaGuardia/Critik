// NoSQL injection + open redirect. Both should trip a finding.
const express = require("express");
const router = express.Router();

function searchAllocations(db, userId, threshold) {
    // MongoDB $where runs server-side JS — interpolating input is injection.
    return db.collection("allocations").find({
        $where: `this.userId == ${userId} && this.stocks > ${threshold}`,
    });
}

function searchByName(db, name) {
    return db.collection("allocations").find({ $where: "this.name == " + name });
}

router.get("/go", (req, res) => {
    res.redirect(req.query.url); // open redirect — target comes from the request
});

module.exports = { router, searchAllocations, searchByName };
