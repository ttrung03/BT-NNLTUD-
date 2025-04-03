let { body, validationResult } = require('express-validator');
const { ERROR_USERNAME, ERROR_EMAIL, ERROR_PASSWORD } = require('./constants');
let util = require('util')

let constants = require('./constants')
let options = {
    password: {
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1
    }
}
module.exports = {
    validate: function (req, res, next) {
        let errors = validationResult(req);
        if (!errors.isEmpty()) {
            CreateSuccessRes(res, 404, errors.array());
        } else {
            next()
        }
    },
    validationSiginUp: [
        body("username").isAlphanumeric().withMessage(ERROR_USERNAME),
        body("password").isStrongPassword(options.password).withMessage(util.format(ERROR_PASSWORD,
            options.password.minLength,
            options.password.minLowercase,
            options.password.minUppercase,
            options.password.minNumbers,
            options.password.minSymbols,
        )),
        body("email").isEmail().withMessage(constants.ERROR_EMAIL)
    ],

    validationSiginIn: [
        body("username").isAlphanumeric().withMessage(ERROR_USERNAME),
        body("password").isStrongPassword(options.password).withMessage(util.format(ERROR_PASSWORD,
            options.password.minLength,
            options.password.minLowercase,
            options.password.minUppercase,
            options.password.minNumbers,
            options.password.minSymbols,
        )),
    ],

    validationCreateUser: [
        body("username").isAlphanumeric().withMessage(ERROR_USERNAME),
        body("password").isStrongPassword(options.password).withMessage(ERROR_PASSWORD),
        body("email").isEmail().withMessage(util.format(ERROR_PASSWORD,
            options.password.minLength,
            options.password.minLowercase,
            options.password.minUppercase,
            options.password.minNumbers,
            options.password.minSymbols,
        )),
        body('role').isIn(['user', 'admin', 'mod']).withMessage("role khong hop le")
    ],

    validationChangePassword: [
        // Kiểm tra mật khẩu hiện tại
        body("currentPassword")
            .notEmpty().withMessage("Mật khẩu hiện tại không được để trống")
            .custom(async (value, { req }) => {
                const user = await User.findById(req.user.id); // Giả sử bạn có thông tin người dùng trong req.user (dùng JWT)
                if (!user) {
                    return Promise.reject("Người dùng không tồn tại");
                }

                // So sánh mật khẩu hiện tại
                const match = await user.comparePassword(value); // Giả sử bạn có hàm comparePassword trong model
                if (!match) {
                    return Promise.reject("Mật khẩu hiện tại không đúng");
                }
            }),

        // Kiểm tra mật khẩu mới
        body("newPassword")
            .notEmpty().withMessage("Mật khẩu mới không được để trống")
            .isStrongPassword(options.password).withMessage(util.format(ERROR_PASSWORD,
                options.password.minLength,
                options.password.minLowercase,
                options.password.minUppercase,
                options.password.minNumbers,
                options.password.minSymbols
            )),

        // Kiểm tra xác nhận mật khẩu mới
        body("confirmPassword")
            .notEmpty().withMessage("Xác nhận mật khẩu không được để trống")
            .custom((value, { req }) => {
                if (value !== req.body.newPassword) {
                    throw new Error("Mật khẩu mới và mật khẩu xác nhận không khớp");
                }
                return true;
            })
    ]
}