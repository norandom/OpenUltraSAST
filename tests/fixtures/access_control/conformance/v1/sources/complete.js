import express from "express";
const app = express();
app.get("/admin", adminHandler);
function adminHandler(req, res) { res.sendStatus(204); }
