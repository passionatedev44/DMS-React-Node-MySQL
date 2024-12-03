const authService = require("../services/authService");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;

exports.login = async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await authService.findUserByEmail(email);
        if (!user) {
            return res.json("User not found");
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.json("Incorrect password");
        }
        jwt.sign(
            {
                id: user.id,
                username: user.username,
                email: user.email,
                role_id: user.role_id,
            },
            JWT_SECRET_KEY,
            { expiresIn: "24h" },
            async (err, token) => {
                if (err) {
                    console.error(err);
                    return res.json({ error: "Token generation failed" });
                }
                await authService.logActivity(
                    user.id,
                    `User: ${email} successfully logged in`
                );
                return res.status(200).json({ token });
            }
        );
    } catch (error) {
        console.error(error);
        return res.json("Internal Server Error");
    }
};

exports.verifyUser = (req, res) => {
    res.json({
        status: "success",
        username: req.username,
        role_id: req.role_id,
    });
};

exports.logout = async (req, res) => {
    try {
        await authService.logActivity(
            req.id,
            `User: ${req.email} successfully logged out`
        );
        res.json({ status: "success" });
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: err.message });
    }
};

exports.signup = async (req, res) => {
    const { username, email, password, role_id } = req.body;

    // Input validation (basic check)
    if (!username || !email || !password || !role_id) {
        return res.status(400).json({ error: "All fields are required" });
    }

    try {
        // Check if the user already exists
        const existingUser = await authService.findUserByEmail(email);
        if (existingUser) {
            return res
                .status(400)
                .json({ error: "User with this email already exists" });
        }

        // Hash the password before storing it
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create the new user
        const newUser = {
            username,
            email,
            password: hashedPassword,
            role_id,
        };

        const createdUser = await authService.createUser(newUser);

        // Log user creation activity
        await authService.logActivity(
            createdUser.id,
            `New user created: ${email}`
        );

        return res.status(201).json({
            message: "User created successfully",
            userId: createdUser.id,
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: "Internal Server Error" });
    }
};
