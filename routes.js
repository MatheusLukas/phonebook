const express = require("express");
const router = express.Router();
const homeController = require("./src/controllers/homeController");
const loginController = require("./src/controllers/loginController");
const contatoController = require("./src/controllers/contatoController");
const { loginRequired } = require("./src/middlewares/middlewares");

// Rotas da home
router.get("/", homeController.index);

// Rotas de login
router.get("/login/index", loginController.index);
router.post("/login/register", loginController.register);
router.post("/login/login", loginController.login);
router.get("/login/logout", loginController.logout);

// Rotas de Contato
router.get("/contato/index", loginRequired, contatoController.index);
router.post("/contato/register", loginRequired, contatoController.register);
router.get("/contato/index/:id", loginRequired, contatoController.editIndex);
router.post("/contato/edit/:id", loginRequired, contatoController.edit);
router.get("/contato/delete/:id", loginRequired, contatoController.delete);

module.exports = router;
