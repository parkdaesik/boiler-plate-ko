const express = require('express');
const app = express();

const port = 4000;

const mongoose = require('mongoose');
mongoose.connect('mongodb+srv://daesik:daesik1234@cluster0-w8xfz.gcp.mongodb.net/test?retryWrites=true&w=majority', {
    useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true, useFindAndModify: false
}).then(() => console.log('MongoDB Connected...'))
.catch(err => console.log(err))

app.get('/', (req, res) => res.send('Hello Wolrd!~~안녕하세요~~'));

app.listen(port, () => console.log('Example app listening on port ${port}!'));