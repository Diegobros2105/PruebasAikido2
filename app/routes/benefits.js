const {
    BenefitsDAO
} = require("../data/benefits-dao");
const {
    environmentalScripts
} = require("../../config/config");
const ESAPI = require("node-esapi");

function BenefitsHandler(db) {
    "use strict";

    const benefitsDAO = new BenefitsDAO(db);

    this.displayBenefits = (req, res, next) => {

        benefitsDAO.getAllNonAdminUsers((error, users) => {

            if (error) return next(error);

            // Sanitize firstName and lastName for all users to prevent stored XSS
            const sanitizedUsers = users.map(user => ({
                ...user,
                firstName: user.firstName ? ESAPI.encoder().encodeForHTML(user.firstName) : "",
                lastName: user.lastName ? ESAPI.encoder().encodeForHTML(user.lastName) : ""
            }));

            return res.render("benefits", {
                users: sanitizedUsers,
                user: {
                    isAdmin: true
                },
                environmentalScripts
            });
        });
    };

    this.updateBenefits = (req, res, next) => {
        const {
            userId,
            benefitStartDate
        } = req.body;

        benefitsDAO.updateBenefits(userId, benefitStartDate, (error) => {

            if (error) return next(error);

            benefitsDAO.getAllNonAdminUsers((error, users) => {
                if (error) return next(error);

                // Sanitize firstName and lastName for all users to prevent stored XSS
                const sanitizedUsers = users.map(user => ({
                    ...user,
                    firstName: user.firstName ? ESAPI.encoder().encodeForHTML(user.firstName) : "",
                    lastName: user.lastName ? ESAPI.encoder().encodeForHTML(user.lastName) : ""
                }));

                const data = {
                    users: sanitizedUsers,
                    user: {
                        isAdmin: true
                    },
                    updateSuccess: true,
                    environmentalScripts
                };

                return res.render("benefits", data);
            });
        });
    };
}

module.exports = BenefitsHandler;
