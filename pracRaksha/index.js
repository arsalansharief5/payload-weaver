import express from "express";

const app = express();


app.get('/',(req,res)=>{
    return res.send("Hello from the other world")
})

app.get('/about',(req,res)=>{
    console.log("Looged the about section");
    return res.send("From about section")
})

app.listen(3000,()=>{
    console.log("Server listening to port 3000")
})