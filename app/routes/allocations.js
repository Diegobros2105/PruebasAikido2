// Lab: shift lines 1/5
// Lab: shift lines 2/5
// Lab: shift lines 3/5
// Lab: shift lines 4/5
// Lab: shift lines 5/5
const AllocationsDAO = require("../data/allocations-dao").AllocationsDAO;
const {
    environmentalScripts
} = require("../../config/config");
const ESAPI = require("node-esapi");

function AllocationsHandler(db) {
    "use strict";

    const allocationsDAO = new AllocationsDAO(db);

    this.displayAllocations = (req, res, next) => {
        /*
        // Fix for A4 Insecure DOR -  take user id from session instead of from URL param
        const { userId } = req.session;
        */
        const {
            userId
        } = req.params;
        const {
            threshold
        } = req.query;

        allocationsDAO.getByUserIdAndThreshold(userId, threshold, (err, allocations) => {
            if (err) return next(err);
            // Sanitize firstName and lastName for all allocations to prevent stored XSS
            const sanitizedAllocations = allocations.map(allocation => ({
                ...allocation,
                firstName: allocation.firstName ? ESAPI.encoder().encodeForHTML(allocation.firstName) : "",
                lastName: allocation.lastName ? ESAPI.encoder().encodeForHTML(allocation.lastName) : ""
            }));
            return res.render("allocations", {
                userId,
                allocations: sanitizedAllocations,
                environmentalScripts
            });
        });
    };
}

module.exports = AllocationsHandler;
