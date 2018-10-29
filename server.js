// 필수 라이브러리
var fs = require('fs');
var express = require('express');
var router = express.Router();
var app = express();
var ejs = require('ejs');

var port = 49200;    // port 번호 49200

app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');

app.listen(port, function() {
    log_comment('OITE 탐색 서버가 시작되었습니다. : ' + port + '번');
});
// 서버 주소를 입력하세요.
app.use('/', express.static('/Users/DingDong/Desktop/ScanBlockchain'));

// http://서버ip주소:49200/result?schText=검색어
router.get('/result', function(req,res) {
    var schText = req.query.schText;
    var index;
    var timeStamp;
    var nonce;
    var hash;
    var previousBlockHash;
    var malwaresHashList = [];

    var malwaresList;
    var filetype;
    var filesize;
    var md5;
    var sha1;
    var sha256;
    var date;
    var first_seen;

    var Data = fs.readFileSync('blockchain.json', 'UTF-8');
    var jsonData = JSON.parse(Data);
    
    for (var i=0; i<Object.keys(jsonData.chain).length; i++) {
        index = jsonData.chain[i].index;
        timeStamp = jsonData.chain[i].timestamp;
        nonce = jsonData.chain[i].nonce;
        hash = jsonData.chain[i].hash;
        previousBlockHash = jsonData.chain[i].previousBlockHash;

        malwaresList = jsonData.chain[i].malwaresList;

        if (schText.replace(/블록|block|번/gi, '').trim().toLowerCase() == index) {
            for (var m=0; m<Object.keys(malwaresList).length; m++) {
                malwaresHashList.push('#' + malwaresList[m].sha256 + '\r\n');
            }
            res.render('result', {schText:schText, index:index, timeStamp:timeStamp, nonce:nonce, hash:hash, previousBlockHash:previousBlockHash, malwaresHashList:malwaresHashList});
            return false;
        }
        else if (schText.toLowerCase() == hash) {
            for (var n=0; n<Object.keys(malwaresList).length; n++) {
                malwaresHashList.push(malwaresList[n].sha256+'\r\n');
            }
            res.render('result', {schText:schText, index:index, timeStamp:timeStamp, nonce:nonce, hash:hash, previousBlockHash:previousBlockHash, malwaresHashList:malwaresHashList});
            return false;
        }
        else if (schText.indexOf('#') == 0) {
            for (var j=0; j<Object.keys(malwaresList).length; j++) {
                filetype = malwaresList[j].filetype;
                filesize = malwaresList[j].filesize;
                md5 = malwaresList[j].md5;
                sha1 = malwaresList[j].sha1;
                sha256 = malwaresList[j].sha256;
                date = malwaresList[j].date;
                first_seen = malwaresList[j].date;
                taglist = malwaresList[j].taglist;
                
                if (schText.replace(/#/g, '').trim().toLowerCase() == filetype || schText.replace(/#/g, '').trim().toUpperCase() == md5 || schText.replace(/#/g, '').trim().toUpperCase() == sha1 || schText.replace(/#/g, '').trim().toUpperCase() == sha256) {
                    res.render('resultMalware', {schText:schText, index:index, timeStamp:timeStamp, filetype:filetype, filesize:filesize, taglist:taglist, md5:md5, sha1:sha1, sha256:sha256, date:date, first_seen:first_seen});
                    return false;
                }
                else {
                    for (var k=0; k<Object.keys(taglist).length; k++) {
                        tag = taglist[k];
                        if (schText.replace(/#/g, '').trim().toLowerCase() == tag) {
                            res.render('resultMalware', {schText:schText, index:index, timeStamp:timeStamp, filetype:filetype, filesize:filesize, taglist:taglist, md5:md5, sha1:sha1, sha256:sha256, date:date, first_seen:first_seen});
                            return false;
                        }
                    }
                }
            }
        }
    }
    res.render('resultNone', {schText:schText});
    return false;
});

app.use('/', router);

// Error Logging 기능
function log_error(error) {
    if (error !== undefined) {
        log_comment("ERROR: " + error);
    }
}

function log_comment(comment) {
    console.log((new Date()) + " " + comment);
}