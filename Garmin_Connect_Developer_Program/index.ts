//---------------------------------------------------------------------------------
//
// app.ts
//
//---------------------------------------------------------------------------------

import express, { Express, Request, Response, NextFunction } from "express";
import bodyParser from "body-parser";
import { config } from "./config.js";
import axios from "axios";
import * as crypto from "crypto";
import { createAuthServiceActor } from "./actors/auth/AuthService.js";
import cors from "cors";
import { AuthService_Messages, AuthService_Name } from "./actors/auth/types.js";
import { initModulo } from "./modulo/modulo.js";
import passport from "passport";
import expressSession from "express-session";
// import * as grant from "grant-express";/
import grant from "grant";
import fs from "fs";
import { decode } from "base64-arraybuffer";
// const { FitParser } = require("fit-file-parser");
// import FitParser from "../dist/fit-file-parser.js";
// import FitParser from "../dist/fit-file-parser/dist/fit-parser.js";
// var FitParser = require('../dist/fit-file-parser/').default;
// import { FitParser } from "fit-file-parser";
// @ts-ignore
// import fitFileParser from "fit-file-parser";
// import fitDecoder from "fit-decoder";
// @ts-ignore
// @ts-ignore
import { Decoder, Stream } from "@garmin-fit/sdk";
// import { Fit } from "@garmin-fit/sdk/fit";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as FacebookStrategy } from "passport-facebook";
import {
  GarminRun,
  GarminUser,
  LoginRequest,
  User,
  UserRole,
  UserType,
  getValidSessionAndUser,
  withTransaction,
} from "./actors/helpers/database.js";

//---------------------------------------------------------------------------------

const app: Express = express();

app.use(
  cors({
    origin: "*",
  })
);
// app.use(express.json());
app.use(bodyParser.json({ limit: "50mb" }));
app.use(bodyParser.urlencoded({ limit: "50mb", extended: true }));

//---------------------------------------------------------------------------------

app.get("/", (req: Request, res: Response) => {
  res.send(`Welcome to ${config.appName}`);
});

app.get("/stripe-test", (req: Request, res: Response) => {
  res.send(`Welcome to STRIPE ${config.appName}`);
});

//---------------------------------------------------------------------------------
// ============================ PASSPORT AUTH =====================================

const GOOGLE_CLIENT_ID =
  "1007041666375-pqg8js7fgq8cq5md36jqtmetqhcqt9v5.apps.googleusercontent.com";
const GOOGLE_CLIENT_SECRET = "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";
const FACEBOOK_CLIENT_ID = "1013705293204130";
const FACEBOOK_CLIENT_SECRET = "8e52fafb5868372d0d4fbbb9c971417c";

passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: "/google/callback",
    },
    (accessToken, refreshToken, profile, callback) => {
      callback(null, profile);
    }
  )
);

// passport.use(
//   new FacebookStrategy(
//     {
//       clientID: FACEBOOK_CLIENT_ID,
//       clientSecret: FACEBOOK_CLIENT_SECRET,
//       callbackURL: "/facebook",
//       profileFields: ["email", "displayName", "name", "picture "],
//     },
//     (accessToken, refreshToken, profile, callback) => {
//       callback(null, profile);
//     }
//   )
// );

passport.serializeUser((user, callback) => {
  callback(null, user);
});

passport.deserializeUser((user: any, callback) => {
  callback(null, user);
});

app.use(
  expressSession({
    secret: "passport_test",
    resave: true,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// --------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------

const conf = {
  defaults: {
    origin: "http://localhost:8080",
    transport: "querystring",
    state: true,
  },
  garmin: {
    key: "fa13e6a8-b4e4-4aa8-909c-7187d2aad98c",
    secret: "tGiizBV1LTo82IRQGSqyf65I5uus5fdT4kA",
    callback: "/garmin/callback",
    scope: ["read_activity", "read_profile"], // Add the necessary scopes
  },
};

app
  .use(
    expressSession({
      secret: "grant_test",
      resave: true,
      saveUninitialized: true,
    })
  )
  .use((grant as any).express(conf));

app.get("/garmin/callback", async (req, res, next) => {
  console.log("req.query", req.query);
  console.log("req.query", (req.session as any).grant);
  console.log("req.grant", (req as any).grant);

  var { user } = await getValidSessionAndUser(
    (req.session as any).grant.dynamic.token
  );

  const timestamp = new Date().getTime();
  function generateRandomString(length: number) {
    const characters =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let randomString = "";
    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * characters.length);
      randomString += characters.charAt(randomIndex);
    }
    return randomString;
  }
  const randomString = generateRandomString(11);

  const httpMethod = "POST";
  const baseUrl =
    "https://connectapi.garmin.com/oauth-service/oauth/access_token";

  const oauthParams: Record<string, string> = {
    oauth_verifier: `${req.query.oauth_verifier}`,
    oauth_consumer_key: "fa13e6a8-b4e4-4aa8-909c-7187d2aad98c",
    oauth_token: `${req.query.oauth_token}`,
    oauth_timestamp: `${timestamp}`,
    oauth_nonce: `${randomString}`,
    oauth_signature_method: "HMAC-SHA1",
  };

  const sortedParams = Object.keys(oauthParams)
    .sort()
    .map(
      (key) =>
        `${encodeURIComponent(key)}=${encodeURIComponent(oauthParams[key])}`
    )
    .join("&");

  const signatureBaseString = `${httpMethod}&${encodeURIComponent(
    baseUrl
  )}&${encodeURIComponent(sortedParams)}`;

  const consumerSecret = "tGiizBV1LTo82IRQGSqyf65I5uus5fdT4kA"; // Replace with your actual consumer secret
  const tokenSecret = (req.session as any).grant.request.oauth_token_secret; // Replace with your actual token secret

  const signatureKey = `${encodeURIComponent(
    consumerSecret
  )}&${encodeURIComponent(tokenSecret)}`;

  const signatureHash = crypto
    .createHmac("sha1", signatureKey)
    .update(signatureBaseString)
    .digest("base64");

  const signature = encodeURIComponent(signatureHash);

  oauthParams["oauth_signature"] = signature;

  console.log("oauthparams and signature", oauthParams, signature);

  const authorizationHeader =
    "OAuth " +
    Object.keys(oauthParams)
      .map((key) => `${key}="${oauthParams[key]}"`)
      .join(", ");

  console.log("Auth Header", authorizationHeader);

  var oauthToken = "";
  var oauthTokenSecret = "";

  // Make the Axios request
  try {
    const response = await axios.post(
      baseUrl,
      {},
      {
        headers: {
          Authorization: authorizationHeader,
        },
      }
    );
    console.log("RESPONSE FROM AXIOS", response?.data);
    const inputString = response?.data;
    var keyValuePairs = inputString.split("&");
    for (var i = 0; i < keyValuePairs.length; i++) {
      var keyValue = keyValuePairs[i].split("=");
      if (keyValue[0] === "oauth_token") {
        oauthToken = keyValue[1];
      } else if (keyValue[0] === "oauth_token_secret") {
        oauthTokenSecret = keyValue[1];
      }
    }
  } catch (error) {
    console.log("ERROR FROM AXIOS", error);
  }

  if (oauthToken && oauthTokenSecret) {
    const getRandomString = generateRandomString(11);
    const getTimestamp = new Date().getTime().toString();
    const newTimestamp = Math.floor(Date.now() / 1000).toString();
    const getHttpMethod = "GET";
    const getBaseUrl = "https://apis.garmin.com/wellness-api/rest/user/id";
    const getOauthParams: Record<string, string> = {
      oauth_consumer_key: "fa13e6a8-b4e4-4aa8-909c-7187d2aad98c",
      oauth_nonce: `${getRandomString}`,
      oauth_signature_method: "HMAC-SHA1",
      oauth_timestamp: `${newTimestamp}`,
      oauth_token: oauthToken,
      oauth_version: "1.0",
    };
    const getSortedParams = Object.keys(getOauthParams)
      .sort()
      .map(
        (key) =>
          `${encodeURIComponent(key)}=${encodeURIComponent(
            getOauthParams[key]
          )}`
      )
      .join("&");
    const getSignatureBaseString = `${getHttpMethod}&${encodeURIComponent(
      getBaseUrl
    )}&${encodeURIComponent(getSortedParams)}`;
    const getConsumerSecret = "tGiizBV1LTo82IRQGSqyf65I5uus5fdT4kA";
    const getTokenSecret = oauthTokenSecret;
    const getSignatureKey = `${encodeURIComponent(
      getConsumerSecret
    )}&${encodeURIComponent(getTokenSecret)}`;
    const getSignatureHash = crypto
      .createHmac("sha1", getSignatureKey)
      .update(getSignatureBaseString)
      .digest("base64");
    const getSignature = encodeURIComponent(getSignatureHash);
    getOauthParams["oauth_signature"] = getSignature;
    const getAuthorizationHeader =
      "OAuth " +
      Object.keys(getOauthParams)
        .map((key) => `${key}="${getOauthParams[key]}"`)
        .join(", ");
    // Make the Axios request
    try {
      const response = await axios.get(
        getBaseUrl,
        // {},
        {
          headers: {
            Authorization: getAuthorizationHeader,
          },
        }
      );
      console.log("RESPONSE FROM AXIOS GET", response?.data);
      const garminUserId = response?.data?.userId;
      if (!user) {
        res.send("User not found");
      }
      if (user && garminUserId) {
        let existingGarminUser = await GarminUser.findOne({
          where: { userId: user!.id },
        });
        if (existingGarminUser) {
          const updatedUser = await withTransaction(async (t) => {
            const modifiedUser = await existingGarminUser!.update(
              {
                garminUserId: garminUserId,
                userAccessToken: oauthToken,
                userAccessTokenSecret: oauthTokenSecret,
                garminSessionStatus: true,
              },
              { transaction: t }
            );
            return modifiedUser;
          });
        } else {
          const newGarminUser = await withTransaction(async (t) => {
            await GarminUser.create(
              {
                userId: user!.id,
                garminUserId: garminUserId,
                userAccessToken: oauthToken,
                userAccessTokenSecret: oauthTokenSecret,
                garminSessionStatus: true,
              },
              { transaction: t }
            );
          });
        }
      }

      console.log("garminUserId", garminUserId);
    } catch (error) {
      console.log("ERROR FROM AXIOS GET", error);
    }
  }

  res.setHeader("Content-Type", "text/html");
  const htmlContent = `<html>
    <head>
        <title>Centered Text</title>
    </head>
    <body style="display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;">
        <div style="text-align: center;">
            <p style="font-size: 50px; color: #333;">Please close the window to complete your garmin connection</p>
        </div>
    </body>
    </html>`;

  // Send an HTML response
  res.send(htmlContent);
  // res.redirect("my-garmin-app-scheme://");
  // res.send("Garmin authentication successful");
  // res.send("Hello from garmin");
  // next();
});

app.post("/garmin/activities", (req, res) => {
  // Get the activity data from the request body.
  const activityData = req.body;

  // Store the activity data in your database.
  console.log("Activity data from garmin", activityData);
  // Respond to the push notification.
  // res.sendStatus(200);
  res.status(200).send();
  console.log("Console test after res");
});

app.post("/garmin/activity-files", async (req, res) => {
  // Get the activity data from the request body.
  console.log("API CALLED FOR FILES");
  const activityData = req.body;

  // Store the activity data in your database.
  console.log("FILE data from garmin", activityData);
  console.log(
    "FILE data from garmin",
    activityData.activityFiles[0].callbackURL
  );

  res.status(200).send();
  console.log("Console test after res");
  // Your backend logic should go here after sending the status 200
  const activityFiles = activityData.activityFiles;
  if (activityFiles.length > 0) {
    console.log("Activity files length");
    activityFiles.map(async (file: any) => {
      console.log("Mapping started", file);
      const garminUser = await GarminUser.findOne({
        where: { garminUserId: file.userId },
      });
      console.log("Garmin user", garminUser);
      if (garminUser) {
        console.log("Garmin user found");
        const newGarminRun = await withTransaction(async (t) => {
          await GarminRun.create(
            {
              userId: garminUser.userId,
              garminUserId: garminUser.garminUserId,
              userAccessToken: garminUser.userAccessToken,
              userAccessTokenSecret: garminUser.userAccessTokenSecret,
              activityName: file.activityName,
              callbackURL: file.callbackURL,
              fileDownloadStatus: false,
              garminCreationTime: file.startTimeInSeconds,
            },
            { transaction: t }
          );
        });
        const userActivities = await GarminRun.findAll({
          where: { userId: garminUser.userId, fileDownloadStatus: false },
        });
        if (userActivities.length) {
          userActivities.map(async (item: GarminRun) => {
            const url = item.callbackURL;
            const parsedUrl = new URL(url);
            const getBaseUrl = `${parsedUrl.origin}${parsedUrl.pathname}`;
            const id = parsedUrl.searchParams.get("id");
            const token = parsedUrl.searchParams.get("token");
            const getHttpMethod = "GET";
            const getRandomString = generateRandomString(11);
            const newTimestamp = Math.floor(Date.now() / 1000).toString();
            const tokenString = token;
            const idString = `id=${id}&`;
            const tokenMainString = `&token=${tokenString}`;
            const getOauthParams: Record<string, string> = {
              oauth_consumer_key: config.garmin.consumerKey,
              oauth_nonce: `${getRandomString}`,
              oauth_signature_method: "HMAC-SHA1",
              oauth_timestamp: `${newTimestamp}`,
              oauth_token: garminUser.userAccessToken,
              oauth_version: "1.0",
            };
            const getSortedParams = Object.keys(getOauthParams)
              .sort()
              .map(
                (key) =>
                  `${encodeURIComponent(key)}=${encodeURIComponent(
                    getOauthParams[key]
                  )}`
              )
              .join("&");
            const getSignatureBaseString = `${getHttpMethod}&${encodeURIComponent(
              getBaseUrl
            )}&${encodeURIComponent(idString)}${encodeURIComponent(
              getSortedParams
            )}${encodeURIComponent(tokenMainString)}`;
            const getConsumerSecret = config.garmin.consumerSecret;
            // const getTokenSecret = item.userAccessTokenSecret;
            const getTokenSecret = garminUser.userAccessTokenSecret;
            const getSignatureKey = `${encodeURIComponent(
              getConsumerSecret
            )}&${encodeURIComponent(getTokenSecret)}`;
            const getSignatureHash = crypto
              .createHmac("sha1", getSignatureKey)
              .update(getSignatureBaseString)
              .digest("base64");
            const getSignature = encodeURIComponent(getSignatureHash);
            getOauthParams["oauth_signature"] = getSignature;
            const getAuthorizationHeader =
              "OAuth " +
              Object.keys(getOauthParams)
                .map((key) => `${key}="${getOauthParams[key]}"`)
                .join(", ");
            const newURL = item.callbackURL;
            //
            var data;
            try {
              const response = await axios.get(newURL, {
                headers: {
                  Authorization: getAuthorizationHeader,
                },
                responseType: "arraybuffer",
              });
              data = response?.data;
              const dataToDatabase = Buffer.from(data, "binary");
              await withTransaction(async (t) => {
                await item!.update(
                  {
                    runDataBlob: dataToDatabase,
                  },
                  { transaction: t }
                );
              });
              const runBlobDataToParse = await GarminRun.findByPk(item.id);
              console.log("type ", typeof runBlobDataToParse?.runDataBlob);
              const file = runBlobDataToParse?.runDataBlob;
              const buffer = file;
              const stream = Stream.fromBuffer(buffer);
              const decoder = new Decoder(stream);

              console.log("isFIT (instance method): " + decoder.isFIT());
              console.log("checkIntegrity: " + decoder.checkIntegrity());

              const { messages, errors } = decoder.read({
                mesgListener: (messageNumber: any, message: any) => {
                  if (messageNumber === 7) {
                    return message;
                  }
                },
              });
              const jsonV = JSON.stringify(messages);

              const jsn = JSON.parse(jsonV);

              type Timestamp = string;
              type Latitude = number;
              type Longitude = number;
              type Seconds = number;
              type Meters = number;
              type MetersPerSecond = number;

              function convertToUnix(date: string): number {
                var unixTimestamp = Date.parse(date) / 1000;
                return unixTimestamp;
              }

              let runDetails = {
                startTime: convertToUnix(jsn.fileIdMesgs[0].timeCreated),
                timeInSeconds: jsn.activityMesgs[0].totalTimerTime,
                distanceInMeters: jsn.sessionMesgs.reduce(
                  (sum: any, item: any) => sum + item.totalDistance,
                  0
                ),
                speedInMeterPerSecond:
                  jsn.sessionMesgs.reduce(
                    (sum: any, item: any) => sum + item.avgSpeed,
                    0
                  ) / jsn.sessionMesgs.length,
                endTime: convertToUnix(jsn.activityMesgs[0].timestamp),
                runSegments: [],
              };

              function groupRecordsByDistance(records: any) {
                const distanceGroups = [];
                let currentGroup: any[] = [];

                let multiplier = 1;
                records.forEach((record: any) => {
                  let flag = false;
                  if (record.distance >= 1000 * multiplier) {
                    // distanceGroups.push([...currentGroup]);
                    currentGroup.push(record);
                    distanceGroups.push([...currentGroup]);
                    currentGroup = [];
                    multiplier++;
                    flag = true;
                  }
                  if (!flag) {
                    currentGroup.push(record);
                  }
                });

                if (currentGroup.length > 0) {
                  distanceGroups.push([...currentGroup]);
                }

                return distanceGroups;
              }

              const groupedRecords = groupRecordsByDistance(jsn.recordMesgs);

              const result = {
                runSegments: groupedRecords.map((group, index) => {
                  const startTime: Timestamp = group[0].timestamp;
                  const endTime: Timestamp = group[group.length - 1].timestamp;
                  const timeInSeconds: Seconds =
                    Math.abs(
                      new Date(startTime as any).getTime() -
                        new Date(endTime as any).getTime()
                    ) / 1000;
                  const distanceInMeters: Meters =
                    group[group.length - 1].distance - 1000 * index;
                  const speedInMeterPerSecond: MetersPerSecond =
                    distanceInMeters / timeInSeconds;

                  return {
                    startTime: convertToUnix(startTime.toString()),
                    timeInSeconds: timeInSeconds,
                    distanceInMeters: distanceInMeters,
                    speedInMeterPerSecond: speedInMeterPerSecond,
                    endTime: convertToUnix(endTime.toString()),
                    runLocations: group.map((record) => ({
                      a: record.positionLat / 11930465,
                      o: record.positionLong / 11930465,
                      t: convertToUnix(record.timestamp),
                    })),
                  };
                }),
              };

              runDetails.runSegments = result.runSegments as any;
              let runDetailsString = JSON.stringify(runDetails.runSegments);

              await withTransaction(async (t) => {
                await item!.update(
                  {
                    runData: jsonV,
                    fileDownloadStatus: true,
                    parsedRunDetails: JSON.stringify(runDetails),
                  },
                  { transaction: t }
                );
              });
            } catch (error) {
              console.log("ERROR FROM AXIOS GET FILES", error);
            }
          });
        }
      }
    });
  }
});

app.get("/garmin/fetch-user-activity", async (req, res) => {
  const { token } = req.query;
  const { user } = await getValidSessionAndUser(token as string);
  const userActivities = await GarminRun.findAll({
    where: { userId: user!.id, fileDownloadStatus: false },
  });
  const nonSyncedActivities = await GarminRun.findAll({
    where: { userId: user!.id, fileDownloadStatus: true, isSynced: false },
  });
  const garminUser = await GarminUser.findOne({ where: { userId: user!.id } });
  if (
    (userActivities.length && garminUser && nonSyncedActivities.length) ||
    (userActivities.length && garminUser && nonSyncedActivities.length === 0)
  ) {
    var arr: string[] = [];
    userActivities.map(async (item: GarminRun) => {
      const url = item.callbackURL;
      const parsedUrl = new URL(url);
      const getBaseUrl = `${parsedUrl.origin}${parsedUrl.pathname}`;
      const id = parsedUrl.searchParams.get("id");
      const token = parsedUrl.searchParams.get("token");
      const getHttpMethod = "GET";
      const getRandomString = generateRandomString(11);
      const newTimestamp = Math.floor(Date.now() / 1000).toString();
      const tokenString = token;
      const idString = `id=${id}&`;
      const tokenMainString = `&token=${tokenString}`;
      const getOauthParams: Record<string, string> = {
        oauth_consumer_key: config.garmin.consumerKey,
        oauth_nonce: `${getRandomString}`,
        oauth_signature_method: "HMAC-SHA1",
        oauth_timestamp: `${newTimestamp}`,
        oauth_token: garminUser.userAccessToken,
        oauth_version: "1.0",
      };
      const getSortedParams = Object.keys(getOauthParams)
        .sort()
        .map(
          (key) =>
            `${encodeURIComponent(key)}=${encodeURIComponent(
              getOauthParams[key]
            )}`
        )
        .join("&");
      const getSignatureBaseString = `${getHttpMethod}&${encodeURIComponent(
        getBaseUrl
      )}&${encodeURIComponent(idString)}${encodeURIComponent(
        getSortedParams
      )}${encodeURIComponent(tokenMainString)}`;
      const getConsumerSecret = config.garmin.consumerSecret;
      // const getTokenSecret = item.userAccessTokenSecret;
      const getTokenSecret = garminUser.userAccessTokenSecret;
      const getSignatureKey = `${encodeURIComponent(
        getConsumerSecret
      )}&${encodeURIComponent(getTokenSecret)}`;
      const getSignatureHash = crypto
        .createHmac("sha1", getSignatureKey)
        .update(getSignatureBaseString)
        .digest("base64");
      const getSignature = encodeURIComponent(getSignatureHash);
      getOauthParams["oauth_signature"] = getSignature;
      const getAuthorizationHeader =
        "OAuth " +
        Object.keys(getOauthParams)
          .map((key) => `${key}="${getOauthParams[key]}"`)
          .join(", ");
      const newURL = item.callbackURL;
      //
      var data;
      try {
        const response = await axios.get(newURL, {
          headers: {
            Authorization: getAuthorizationHeader,
          },
          responseType: "arraybuffer",
        });
        data = response?.data;
        const dataToDatabase = Buffer.from(data, "binary");
        await withTransaction(async (t) => {
          await item!.update(
            {
              runDataBlob: dataToDatabase,
            },
            { transaction: t }
          );
        });
        const runBlobDataToParse = await GarminRun.findByPk(item.id);
        console.log("type ", typeof runBlobDataToParse?.runDataBlob);
        const file = runBlobDataToParse?.runDataBlob;
        const buffer = file;
        const stream = Stream.fromBuffer(buffer);
        const decoder = new Decoder(stream);

        console.log("isFIT (instance method): " + decoder.isFIT());
        console.log("checkIntegrity: " + decoder.checkIntegrity());

        const { messages, errors } = decoder.read({
          mesgListener: (messageNumber: any, message: any) => {
            if (messageNumber === 7) {
              return message;
            }
          },
        });
        const jsonV = JSON.stringify(messages);

        const jsn = JSON.parse(jsonV);

        type Timestamp = string;
        type Latitude = number;
        type Longitude = number;
        type Seconds = number;
        type Meters = number;
        type MetersPerSecond = number;

        // interface RunLocation {
        //   a: Latitude; // Assuming 'a' stands for latitude
        //   o: Longitude; // Assuming 'o' stands for longitude
        //   t: Timestamp; // Assuming 't' stands for time
        // }

        // interface RunSegment {
        //   startTime: Timestamp;
        //   timeInSeconds: Seconds;
        //   distanceInMeters: Meters;
        //   speedInMeterPerSecond: MetersPerSecond;
        //   endTime: Timestamp;
        //   runLocations: RunLocation[];
        // }

        // interface RunData {
        //   startTime: Timestamp;
        //   timeInSeconds: Seconds;
        //   distanceInMeters: Meters;
        //   speedInMeterPerSecond: MetersPerSecond;
        //   endTime: Timestamp;
        //   runSegments: any[];
        // }

        function convertToUnix(date: string): number {
          var unixTimestamp = Date.parse(date) / 1000;
          return unixTimestamp;
        }

        let runDetails = {
          startTime: convertToUnix(jsn.fileIdMesgs[0].timeCreated),
          timeInSeconds: jsn.activityMesgs[0].totalTimerTime,
          distanceInMeters: jsn.sessionMesgs.reduce(
            (sum: any, item: any) => sum + item.totalDistance,
            0
          ),
          speedInMeterPerSecond:
            jsn.sessionMesgs.reduce(
              (sum: any, item: any) => sum + item.avgSpeed,
              0
            ) / jsn.sessionMesgs.length,
          endTime: convertToUnix(jsn.activityMesgs[0].timestamp),
          runSegments: [],
        };

        function groupRecordsByDistance(records: any) {
          const distanceGroups = [];
          let currentGroup: any[] = [];

          let multiplier = 1;
          records.forEach((record: any) => {
            let flag = false;
            if (record.distance >= 1000 * multiplier) {
              // distanceGroups.push([...currentGroup]);
              currentGroup.push(record);
              distanceGroups.push([...currentGroup]);
              currentGroup = [];
              multiplier++;
              flag = true;
            }
            if (!flag) {
              currentGroup.push(record);
            }
          });

          if (currentGroup.length > 0) {
            distanceGroups.push([...currentGroup]);
          }

          return distanceGroups;
        }

        const groupedRecords = groupRecordsByDistance(jsn.recordMesgs);

        const result = {
          runSegments: groupedRecords.map((group, index) => {
            const startTime: Timestamp = group[0].timestamp;
            const endTime: Timestamp = group[group.length - 1].timestamp;
            const timeInSeconds: Seconds =
              Math.abs(
                new Date(startTime as any).getTime() -
                  new Date(endTime as any).getTime()
              ) / 1000;
            const distanceInMeters: Meters =
              group[group.length - 1].distance - 1000 * index;
            const speedInMeterPerSecond: MetersPerSecond =
              distanceInMeters / timeInSeconds;

            return {
              startTime: convertToUnix(startTime.toString()),
              timeInSeconds: timeInSeconds,
              distanceInMeters: distanceInMeters,
              speedInMeterPerSecond: speedInMeterPerSecond,
              endTime: convertToUnix(endTime.toString()),
              runLocations: group.map((record) => ({
                a: record.positionLat / 11930465,
                o: record.positionLong / 11930465,
                t: convertToUnix(record.timestamp),
              })),
            };
          }),
        };

        runDetails.runSegments = result.runSegments as any;
        let runDetailsString = JSON.stringify(runDetails.runSegments);

        await withTransaction(async (t) => {
          await item!.update(
            {
              runData: jsonV,
              fileDownloadStatus: true,
              parsedRunDetails: runDetailsString,
            },
            { transaction: t }
          );
        });
      } catch (error) {
        console.log("ERROR FROM AXIOS GET FILES", error);
      }
    });
    const returnArr = arr;
    console.log("type of", typeof returnArr, arr);
    const str = await GarminRun.findOne();
    const newStr = JSON.parse(str?.runData ?? "");
    const updatedActivities = await GarminRun.findAll({
      where: { userId: user!.id, fileDownloadStatus: true, isSynced: false },
    });
    const response = {
      status: 200,
      message: true,
      data: updatedActivities,
    };
    res.status(200).json(response);
  } else if (
    nonSyncedActivities.length &&
    garminUser &&
    userActivities.length === 0
  ) {
    const updatedActivities = await GarminRun.findAll({
      where: { userId: user!.id, fileDownloadStatus: true, isSynced: false },
    });
    const response = {
      status: 200,
      message: true,
      data: updatedActivities,
    };
    res.status(200).json(response);
  } else {
    const response = {
      status: 200,
      message: false,
      data: [],
    };
    res.status(200).json(response);
  }
});

function generateRandomString(length: number) {
  const characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let randomString = "";
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    randomString += characters.charAt(randomIndex);
  }
  return randomString;
}

app.get("/garmin/activity-files", async (req, res) => {
  function generateRandomString(length: number) {
    const characters =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let randomString = "";
    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * characters.length);
      randomString += characters.charAt(randomIndex);
    }
    return randomString;
  }
  const getRandomString = generateRandomString(11);
  const newTimestamp = Math.floor(Date.now() / 1000).toString();
  const getBaseUrl = "https://apis.garmin.com/wellness-api/rest/activityFile";
  const urlForSign = "https://apis.garmin.com/wellness-api/rest/activityFile";
  const getHttpMethod = "GET";
  const getOauthParams: Record<string, string> = {
    oauth_consumer_key: "fa13e6a8-b4e4-4aa8-909c-7187d2aad98c",
    oauth_nonce: `${getRandomString}`,
    oauth_signature_method: "HMAC-SHA1",
    oauth_timestamp: `${newTimestamp}`,
    oauth_token: "887b6fee-2f11-41c2-9f7a-c0d70d67a0c3",
    oauth_version: "1.0",
  };
  const id = "297495287713";
  const token = "AAAAAGUaqoOc8b_K";
  const tokenString = token;
  const idString = `id=${id}&`;
  const tokenMainString = `&token=${tokenString}`;
  const getSortedParams = Object.keys(getOauthParams)
    .sort()
    .map(
      (key) =>
        `${encodeURIComponent(key)}=${encodeURIComponent(getOauthParams[key])}`
    )
    .join("&");
  const getSignatureBaseString = `${getHttpMethod}&${encodeURIComponent(
    getBaseUrl
  )}&${encodeURIComponent(idString)}${encodeURIComponent(
    getSortedParams
  )}${encodeURIComponent(tokenMainString)}`;
  const getConsumerSecret = "tGiizBV1LTo82IRQGSqyf65I5uus5fdT4kA";
  const getTokenSecret = "JvRqEnOs30jFPDMqBCD5W81SpJGKRCQIP5d";
  const getSignatureKey = `${encodeURIComponent(
    getConsumerSecret
  )}&${encodeURIComponent(getTokenSecret)}`;
  const getSignatureHash = crypto
    .createHmac("sha1", getSignatureKey)
    .update(getSignatureBaseString)
    .digest("base64");
  const getSignature = encodeURIComponent(getSignatureHash);
  getOauthParams["oauth_signature"] = getSignature;
  const getAuthorizationHeader =
    "OAuth " +
    Object.keys(getOauthParams)
      .map((key) => `${key}="${getOauthParams[key]}"`)
      .join(", ");
  // Make the Axios request

  console.log(
    "getAuthHeader, getSignature,",
    getAuthorizationHeader,
    getSignature,
    getSignatureBaseString
  );
  const newURL = `https://apis.garmin.com/wellness-api/rest/activityFile?id=${id}&token=${token}`;

  var data;
  try {
    const response = await axios.get(
      newURL,
      // {},
      {
        headers: {
          Authorization: getAuthorizationHeader,
        },
        responseType: "arraybuffer",
      }
    );
    // console.log("RESPONSE FROM AXIOS GET FILES", response?.data);
    // -------------------------------------
    // Directly converting to json.
    data = response?.data;

    // const encoder = new TextEncoder();
    // const byteArray = encoder.encode(data);

    // // Convert the byte array to a hexadecimal format
    // const hexArray = Array.from(
    //   byteArray,
    //   (byte) => "0x" + byte.toString(16).padStart(2, "0")
    // );

    // const binaryData = decode(data);
    // const fit = new Fit(data);
    // const decodedFitFile = await fit.decode();
    // const jsonData = JSON.stringify(decodedFitFile);

    // console.log(jsonData);
    // const dataN = Buffer.from(data, "binary");
    // const dataN = Buffer.from(binaryData);

    // const fitParser = new fitFileParser();

    // // Parse the FIT file data using FitParser.
    // const decodedFitFile = await fitParser.parse(dataN);

    // // Convert the parsed data to JSON.
    // const jsonData = JSON.stringify(decodedFitFile);

    // const fitParser = new FitParser();

    // // Decode the FIT file.
    // const decodedFitFile = await FitParser.parse(dataN);

    // // Parse the decoded FIT file to JSON.
    // const jsonData = JSON.stringify(decodedFitFile);

    // console.log(jsonData);
    // console.log("type of data", typeof data, typeof dataN);
    // console.log("type of data", typeof data, typeof data);
    // const file = response?.data as Buffer;
    // const buffer = file;
    // const bytes = new Uint8Array(dataN);
    // const bytes = new Uint8Array(data);

    // const stream = Stream.fromByteArray(bytes);
    // const stream = Stream.fromArrayBuffer(data);
    // const stream = Stream.fromArrayBuffer(bytes.buffer);
    // const stream = Stream.fromByteArray(hexArray);
    // console.log("BUFFER", bytes, dataN);
    // console.log("BUFFER", bytes, typeof data, dataN);
    // const stream = await Stream.fromBuffer(buffer);
    // const stream = await Stream.fromBuffer(data);

    // const decoder = new Decoder(stream);
    // console.log("isFIT (instance method): " + decoder.isFIT());
    // console.log("checkIntegrity: " + decoder.checkIntegrity());
    // const messages = decoder.read();
    // const jsonV = JSON.stringify(messages);
    // console.log(jsonV);
    // -------------------------------------
    async function storeFitFile(fitFile: any, filename: any) {
      // Create a new directory for the FIT file if it doesn't exist
      const directory = "./fit-files";
      if (!fs.existsSync(directory)) {
        fs.mkdirSync(directory);
      }

      // Write the FIT file to the directory
      const filePath = `${directory}/${filename}`;
      fs.writeFileSync(filePath, fitFile, "binary");
    }
    const filename = `${newTimestamp}.fit`;
    await storeFitFile(response?.data, filename);

    await fs.readFile(`../server-new/fit-files/${filename}`, (err, data) => {
      // fs.readFile("../server-new/fit-files/SpeedCoachJustGo.fit", (err, data) => {
      if (err) {
        // Handle the error.
        console.log("err,", err);
      } else {
        // The file was read successfully.
        console.log("type", typeof data);
        const file = data;
        const buffer = file;
        const stream = Stream.fromBuffer(buffer);
        const decoder = new Decoder(stream);

        console.log("isFIT (instance method): " + decoder.isFIT());
        console.log("checkIntegrity: " + decoder.checkIntegrity());

        const { messages, errors } = decoder.read({
          mesgListener: (messageNumber: any, message: any) => {
            if (messageNumber === 7) {
              return message;
            }
            // console.log(messageNumber, message);
          },
          // applyScaleAndOffset: true,
          // expandSubFields: true,
          // expandComponents: true,
          // convertTypesToStrings: true,
          // convertDateTimesToDates: true,
          // includeUnknownData: false,
          // mergeHeartRates: true,
        });
        // const messages = decoder.read();
        const jsonV = JSON.stringify(messages);
        console.log(jsonV);
        // // ------------------------------
      }
    });
  } catch (error) {
    console.log("ERROR FROM AXIOS GET FILES", error);
  }
});

app.get("/garmin/fit-convert", async (req, res) => {
  console.log("API CALLED FOR COVERT");
  try {
    // const fitFile = "1696106822";
    // const fitFile = "SpeedCoachJustGo";
    const fitFile = "1696314026";
    // const fitFile = "1696106470";
    fs.readFile(`../server-new/fit-files/${fitFile}.fit`, (err, data) => {
      // fs.readFile("../server-new/fit-files/SpeedCoachJustGo.fit", (err, data) => {
      if (err) {
        // Handle the error.
        console.log("err,", err);
      } else {
        // The file was read successfully.
        console.log("type", typeof data);
        const file = data;
        const buffer = file;
        const stream = Stream.fromBuffer(buffer);
        // const bytes = [
        //   0x0e, 0x10, 0xd9, 0x07, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x46, 0x49,
        //   0x54, 0x91, 0x33, 0x00, 0x00,
        // ];
        // const bytes = (data as Buffer).toBytes();
        // const bytes = new Uint8Array(data);

        // const stream = Stream.fromByteArray(bytes);
        const decoder = new Decoder(stream);

        // const decoder = new Decoder(stream);
        console.log("isFIT (instance method): " + decoder.isFIT());
        console.log("checkIntegrity: " + decoder.checkIntegrity());

        const { messages, errors } = decoder.read({
          mesgListener: (messageNumber: any, message: any) => {
            if (messageNumber === 7) {
              return message;
            }
            // console.log(messageNumber, message);
          },
          // applyScaleAndOffset: true,
          // expandSubFields: true,
          // expandComponents: true,
          // convertTypesToStrings: true,
          // convertDateTimesToDates: true,
          // includeUnknownData: false,
          // mergeHeartRates: true,
        });
        // const messages = decoder.read();
        const jsonV = JSON.stringify(messages);
        console.log(jsonV);
        // // ------------------------------
        // const fileN = data;
        // // const bufferN = file.buffer;

        // // Convert the buffer to an ArrayBuffer
        // const arrayBuffer = new ArrayBuffer(buffer.byteLength);
        // const view = new Uint8Array(arrayBuffer);
        // view.set(buffer);

        // // Call the fit2json() function with the ArrayBuffer
        // const jsonRaw = fitDecoder.fit2json(arrayBuffer);
        // const jsonN = fitDecoder.parseRecords(jsonRaw);

        // // const jsonRaw = fitDecoder.fit2json(buffer);

        // // // parseRecords converts raw JSON format into readable format using current
        // // // Global FIT Profile (SDK 21.47.00)
        // // // It also performs simple conversions for some data formats like time, distance, coordinates.
        // // const jsonN = fitDecoder.parseRecords(jsonRaw);
        // console.log("JSON", jsonN);
      }
    });

    // const file = await fs.readFile("../fit-files/1696102842.fit");
    // fs.readFile("../server-new/fit-files/1696102842.fit", (err, data) => {
    //   if (err) {
    //     // Handle the error.
    //     console.log("err,", err);
    //   } else {
    //     // The file was read successfully.
    //     const file = data;
    //     const buffer = file.buffer;
    //     const json = fitDecoder.parseRecords(fitDecoder.fit2json(buffer));
    //     const jsonStr = JSON.stringify(json, null, 2);
    //     console.log("json, jsonStr", json, jsonStr);
    //   }
    // });

    // Path to the input FIT file
    const fitFilePath: string = "../server-new/fit-files/1696102842.fit";

    // Read the FIT file
    // fs.readFile(fitFilePath, (err, data) => {
    //   if (err) {
    //     console.error("Error reading FIT file:", err);
    //     return;
    //   }

    //   // Parse the FIT data

    //   const fitParser: any = new FitParser();
    //   fitParser.parse(data.buffer, (error: any, output: any) => {
    //     if (error) {
    //       console.error("Error parsing FIT file:", error);
    //       return;
    //     }

    //     // Convert FIT data to JSON
    //     const jsonData: string = JSON.stringify(output, null, 2);
    //     console.log(jsonData);

    //     // Write the JSON data to a file
    //     fs.writeFile("output.json", jsonData, (writeError) => {
    //       if (writeError) {
    //         console.error("Error writing JSON file:", writeError);
    //       } else {
    //         console.log("FIT file converted to JSON and saved as output.json");
    //       }
    //     });
    //   });
    // });
  } catch (error) {
    console.log("Error is", error);
  }
});

app.post("/garmin/activity-details", (req, res) => {
  // Get the activity data from the request body.
  const activityData = req.body;

  // Store the activity data in your database.
  console.log("Activity details from garmin", activityData);
  // Respond to the push notification.
  // res.sendStatus(200);
  res.status(200).send();
  console.log("Console test after res");
});

app.post("/garmin/deregistration", (req, res) => {
  const data = req.body;

  // Store the activity data in your database.
  console.log("Deregistarion detail", data);
  res.status(200).send();
  console.log("Console test after res");
});

app.post("/garmin/user-permissions", (req, res) => {
  const data = req.body;

  // Store the activity data in your database.
  console.log("User permissions", data);
  res.status(200).send();
  console.log("Console test after res");
});

app.get("/testJson", async (req, res) => {
  // const data = req.body;
  const data = await GarminRun.findByPk("a5e70260-3bcb-4641-a1e1-78683e99c85e");
  const jsn = JSON.parse(data?.runData ?? "{}");
  // Store the activity data in your database.
  type Timestamp = string;
  type Latitude = number;
  type Longitude = number;
  type Seconds = number;
  type Meters = number;
  type MetersPerSecond = number;

  interface RunLocation {
    a: Latitude; // Assuming 'a' stands for latitude
    o: Longitude; // Assuming 'o' stands for longitude
    t: Timestamp; // Assuming 't' stands for time
  }

  interface RunSegment {
    startTime: Timestamp;
    timeInSeconds: Seconds;
    distanceInMeters: Meters;
    speedInMeterPerSecond: MetersPerSecond;
    endTime: Timestamp;
    runLocations: RunLocation[];
  }

  interface RunData {
    startTime: Timestamp;
    timeInSeconds: Seconds;
    distanceInMeters: Meters;
    speedInMeterPerSecond: MetersPerSecond;
    endTime: Timestamp;
    runSegments: any[];
  }

  function convertToUnix(date: string): number {
    var unixTimestamp = Date.parse(date) / 1000;
    return unixTimestamp;
  }

  let runDetails = {
    startTime: convertToUnix(jsn.fileIdMesgs[0].timeCreated),
    timeInSeconds: jsn.activityMesgs[0].totalTimerTime,
    distanceInMeters: jsn.sessionMesgs.reduce(
      (sum: any, item: any) => sum + item.totalDistance,
      0
    ),
    speedInMeterPerSecond:
      jsn.sessionMesgs.reduce((sum: any, item: any) => sum + item.avgSpeed, 0) /
      jsn.sessionMesgs.length,
    endTime: convertToUnix(jsn.activityMesgs[0].timestamp),
    runSegments: [],
  };
  type myObject = RunLocation[];
  interface CurrentObj {
    myObject: myObject;
    totalDistance: number;
  }
  let currentObject: CurrentObj = {
    myObject: [],
    totalDistance: 0,
  };
  const runSegments: {
    endTime: any;
    startTime: any;
    timeInSeconds: number;
    distanceInMeters: number;
    speedInMeterPerSecond: number;
    runLocations: RunLocation[];
  }[] = [];

  function groupRecordsByDistance(records: any) {
    const distanceGroups = [];
    let currentGroup: any[] = [];

    let multiplier = 1;
    records.forEach((record: any) => {
      let flag = false;
      if (record.distance >= 1000 * multiplier) {
        // distanceGroups.push([...currentGroup]);
        currentGroup.push(record);
        distanceGroups.push([...currentGroup]);
        currentGroup = [];
        multiplier++;
        flag = true;
      }
      if (!flag) {
        currentGroup.push(record);
      }
    });

    if (currentGroup.length > 0) {
      distanceGroups.push([...currentGroup]);
    }

    return distanceGroups;
  }

  const groupedRecords = groupRecordsByDistance(jsn.recordMesgs);

  const result = {
    runSegments: groupedRecords.map((group, index) => {
      // console.log("index", index);
      const startTime: Timestamp = group[0].timestamp;
      const endTime: Timestamp = group[group.length - 1].timestamp;
      const timeInSeconds: Seconds =
        Math.abs(
          new Date(startTime as any).getTime() -
            new Date(endTime as any).getTime()
        ) / 1000;
      const distanceInMeters: Meters =
        group[group.length - 1].distance - 1000 * index;
      const speedInMeterPerSecond: MetersPerSecond =
        distanceInMeters / timeInSeconds;

      return {
        startTime: convertToUnix(startTime.toString()),
        timeInSeconds: timeInSeconds,
        distanceInMeters: distanceInMeters,
        speedInMeterPerSecond: speedInMeterPerSecond,
        endTime: convertToUnix(endTime.toString()),
        runLocations: group.map((record) => ({
          a: record.positionLat / 11930465,
          o: record.positionLong / 11930465,
          t: convertToUnix(record.timestamp),
        })),
      };
    }),
  };

  runDetails.runSegments = result.runSegments as any;

  // console.log(JSON.stringify(result, null, 2));

  res.status(200).json(runDetails);
  // res.status(200).json({});
  console.log("Console test after res");
});

app.get("/gar", async (req, res, next) => {
  // const { user } = await getValidSessionAndUser(input!.token);
  // const garminRunId = input!.garminRunId;
  const user = "74cb0765-dd63-4da5-834b-8d47201397d0";
  let garminRunId = "0a4180dc-5079-4315-be10-8b2c71a015d0";
  const garminRun = await GarminRun.findOne({
    where: { id: garminRunId, userId: user },
  });
  console.log(">>>>>> GET GARMIN RUN", garminRun?.activityName);
  const runDetailsString = garminRun?.parsedRunDetails;
  console.log(runDetailsString);
  const runDetails = JSON.parse(runDetailsString ?? "{}");
  console.log(runDetails);
  res.status(200).json(runDetails);
});

app.get("/pro", async (req, res, next) => {
  let garminRunId = "0a4180dc-5079-4315-be10-8b2c71a015d0";
  try {
    // Sending the buffer to the new service and awaiting its response
    const garminRun = await GarminRun.findByPk(garminRunId);
    const file = garminRun?.runDataBlob;
    const buffer = file;
    const response = await axios.post("http://localhost:4000/process-buffer", {
      data: buffer?.toString("base64"),
    }); // converting buffer to base64 string for transmission
    const jsonV = response.data;

    // console.log("Json v", jsonV);
    res.status(200).json(jsonV);
    // Now you can continue using the jsonV...
  } catch (error) {
    console.error("Error invoking the new API", error);
  }
});

// --------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------
// --------------------------------------------------------------------------------------------------------

// Routes
app.get(
  "/login/google",
  (req, res, next) => {
    // Add data to the request object
    (req as any).clientUrl = "Hello from /login/google!";
    // Continue with the authentication process
    next();
  },
  passport.authenticate("google", { scope: ["profile email"] })
);
// app.get(
//   "/login/facebook",
//   passport.authenticate("facebook", { scope: ["email"] })
// );

// app.get(
//   "/google/callback",
//   passport.authenticate("google", {
//     successRedirect: `${config.passportAuth.clientUrl}/terms&conditions`,
//     failureRedirect: `${config.passportAuth.clientUrl}/privacy-policy`,
//   })
//   // (req, res) => {
//   //   // console.log("call back", req.user);
//   //   // console.log("call back body", (req as any).clientUrl);
//   //   // res.send({ message: true });
//   //   // res.redirect("/");
//   // }
// );

app.get(
  "/google/callback",
  passport.authenticate("google"),
  async (req, res) => {
    if (req.user) {
      console.log("External email", (req.user as any)._json.email);
      const externalEmail = (req.user as any)._json.email;
      let user = await User.findOne({
        where: { email: externalEmail },
      });
      let loginRequest: LoginRequest;
      if (!user) {
        const newUser = await withTransaction(async (t) => {
          user = await User.create(
            {
              email: externalEmail,
              firstName: (req.user as any)._json.given_name,
              lastName: (req.user as any)._json.family_name,
              userType: UserType.Individual,
              role: UserRole.IndividualUser,
            },
            { transaction: t }
          );
        });

        await withTransaction(async (t) => {
          loginRequest = await LoginRequest.create(
            {
              userId: user!.id,
              socialNetworkId: (req.user as any)._json.sub,
            },
            { transaction: t }
          );
        });
      } else {
        await withTransaction(async (t) => {
          loginRequest = await LoginRequest.create(
            {
              userId: user!.id,
              socialNetworkId: (req.user as any)._json.sub,
            },
            { transaction: t }
          );
        });
      }
      res.redirect(
        `${config.passportAuth.clientUrl}?id=${(req.user as any).id}`
      );
    } else {
      res.redirect(`${config.passportAuth.clientUrl}/register`);
    }
  }
);

// app.get("/facebook", passport.authenticate("facebook"), (req, res) => {
//   res.redirect("/");
// });

app.get("/logout", (req, res, next: NextFunction) => {
  req.logout((err) => {
    if (err) {
      // Handle error
      console.error("Error during logout:", err);
      return next(err); // Pass the error to the next middleware
    }
    // Redirect or perform other actions after logout
    console.log("Logged out successfully");
    res.redirect("/"); // Redirect to home page after successful logout
  });
});

app.get("/loginTest", (req, res) => {
  console.log(req.user);
  res.send(
    req.user
      ? req.user
      : "Not logged in, you can login using google or facebook"
  );
});

// ============================ PASSPORT AUTH =====================================
//---------------------------------------------------------------------------------

console.log("CONFIG:", config);
initModulo({ config, app });

//---------------------------------------------------------------------------------

app.listen(config.port, () => {
  console.log(
    `⚡️[server]: Server is running at http://localhost:${config.port}`
  );
});

//---------------------------------------------------------------------------------
