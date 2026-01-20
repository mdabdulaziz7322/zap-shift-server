const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const admin = require("firebase-admin");
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const { default: Stripe } = require('stripe');

dotenv.config();

const stripe = new Stripe(process.env.PAYMENT_GATEWAY_KEY);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ---------------- FIREBASE ADMIN INIT ----------------
const decodedKey = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8');
const serviceAccount = JSON.parse(decodedKey);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

// ---------------- MONGODB INIT ----------------
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.j19qmx9.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});


async function startServer() {
    try {
        await client.connect();
        console.log("✅ Connected to MongoDB");

        const db = client.db('parcelDB');
        const parcelsCollection = db.collection('parcels');
        const paymentsCollection = db.collection('payments')
        const usersCollection = db.collection('users')
        const trackingsCollection = db.collection('tracking');
        const ridersCollection = db.collection('riders')
        const notificationsCollection = db.collection('notifications');

        // custom middlewares

        const verifyFBToken = async (req, res, next) => {
            const authHeader = req.headers.authorization;
            if (!authHeader) {
                return res.status(401).send({ massage: 'Unauthorized access' })
            }
            const token = authHeader.split(' ')[1];
            if (!token) {
                return res.status(401).send({ massage: 'Unauthorized access' })
            }

            // verify the token

            try {
                const decoded = await admin.auth().verifyIdToken(token);
                req.decoded = decoded;
                next();
            }
            catch (error) {
                return res.status(403).send({ massage: 'Forbidden access' })
            }

        }

        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;

            const user = await usersCollection.findOne(
                { email },
                { projection: { role: 1 } }
            );

            if (user?.role !== "admin") {
                return res.status(403).send({ message: "Admin access only" });
            }

            next();
        };
        const verifyRider = async (req, res, next) => {
            const email = req.decoded.email;

            const user = await usersCollection.findOne(
                { email },
                { projection: { role: 1 } }
            );

            if (user?.role !== "rider") {
                return res.status(403).send({ message: "Rider access only" });
            }

            next();
        };

        const createNotification = async ({ userType, userEmail, message, type }) => {
            try {
                const notification = {
                    userType,        // "user", "rider", "admin"
                    userEmail: userEmail || null, // if specific to a user
                    message,
                    type,            // "parcel", "assignment", "cashout"
                    is_read: false,
                    created_at: new Date(),
                };

                const result = await notificationsCollection.insertOne(notification);
                return result.insertedId;
            } catch (error) {
                console.error("Notification error:", error);
            }
        };



        app.get('/', (req, res) => {
            res.send('Welcome to parcel world!');
        });

        // GET /users/search?email=gmail
        app.get("/users/search", async (req, res) => {
            try {
                const { email } = req.query;

                if (!email) {
                    return res.status(400).json({ message: "Email query is required" });
                }

                const users = await usersCollection
                    .find({
                        email: { $regex: email, $options: "i" } // ✅ PARTIAL + IGNORE CASE
                    })
                    .limit(10) // ✅ ONLY 10 USERS
                    .toArray();

                res.json(users);
            } catch (error) {
                console.error(error);
                res.status(500).json({ message: "Server error" });
            }
        });
        // GET role by email
        app.get("/users/role", async (req, res) => {
            const email = req.query.email;

            if (!email) {
                return res.status(400).json({ message: "Email is required" });
            }

            const user = await usersCollection.findOne(
                { email },
                { projection: { role: 1 } }
            );

            if (!user) {
                return res.json({ role: "user" }); // default role
            }

            res.json({ role: user.role });
        });


        app.post('/users', async (req, res) => {
            const email = req.body.email;

            const userExist = await usersCollection.findOne({ email });
            if (userExist) {
                return res.status(200).send({
                    message: 'User already exists',
                    inserted: false
                });
            }

            const user = req.body;
            const result = await usersCollection.insertOne(user);
            res.send(result);
        });

        // PATCH /users/:id/role
        app.patch("/users/:id/role", async (req, res) => {
            const { id } = req.params;
            const { role } = req.body;

            if (!["admin", "user", "rider"].includes(role)) {
                return res.status(400).json({ message: "Invalid role" });
            }

            const result = await usersCollection.updateOne(
                { _id: new ObjectId(id) },
                { $set: { role } }
            );

            res.json({ success: true });
        });


        // parcel Api endpoints

        app.get('/parcels/:id', async (req, res) => {
            try {
                const { id } = req.params;
                const parcel = await parcelsCollection.findOne({ _id: new ObjectId(id) });
                if (!parcel) return res.status(404).json({ error: 'Parcel not found' });
                res.json(parcel);
            } catch (err) {
                console.error(err);
                res.status(500).json({ error: 'Server error' });
            }
        });

        app.get("/parcels", verifyFBToken, async (req, res) => {
            try {
                const { email, type } = req.query;
                let query = {};
                let sortOption = { created_at: -1 };

                if (type === "assignable") {
                    // 🔐 ADMIN ONLY
                    const user = await usersCollection.findOne(
                        { email: req.decoded.email },
                        { projection: { role: 1 } }
                    );

                    if (user?.role !== "admin") {
                        return res.status(403).send({ message: "Admin access only" });
                    }

                    query = {
                        payment_status: "paid",
                        delivery_status: "not collected",
                    };
                } else {
                    // 👤 USER PARCELS
                    if (req.decoded.email !== email) {
                        return res.status(403).send({ message: "Forbidden access" });
                    }
                    query = { created_by: email };
                }

                const parcels = await parcelsCollection
                    .find(query)
                    .sort(sortOption)
                    .toArray();

                res.send(parcels);
            } catch (error) {
                res.status(500).json({ message: error.message });
            }
        });


        app.post('/parcels', async (req, res) => {
            try {
                const newParcel = req.body;
                const result = await parcelsCollection.insertOne(newParcel);
                res.send(result);
            } catch (error) {
                res.status(500).json({ message: error.message });
            }
        });

        // Assign rider to parcel
        app.patch("/parcels/:id/assign-rider", async (req, res) => {
            try {
                const { id } = req.params;
                const { riderId, riderName, riderEmail } = req.body;

                const parcel = await parcelsCollection.findOne({ _id: new ObjectId(id) });
                if (!parcel) return res.status(404).send({ message: "Parcel not found" });

                const result = await parcelsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    {
                        $set: {
                            assigned_rider_id: riderId,
                            assigned_rider_name: riderName,
                            assigned_rider_email: riderEmail,
                            delivery_status: "Rider Assigned",
                        },
                    }
                );

                // 🔔 Notify rider
                await createNotification({
                    userType: "rider",
                    userEmail: riderEmail,
                    message: `You have been assigned parcel ${parcel.tracking_id}`,
                    type: "assignment",
                });

                res.send(result);
            } catch (error) {
                res.status(500).json({ message: error.message });
            }
        });



        app.delete('/parcels/:id', async (req, res) => {
            try {
                const id = req.params.id;

                const result = await parcelsCollection.deleteOne({
                    _id: new ObjectId(id)
                });

                res.send(result);
            }
            catch (error) {
                res.status(500).json({ message: error.message });
            }

        });

        // ✅ update status after rider task
        app.patch("/parcels/:id/delivery-status", verifyFBToken, verifyRider, async (req, res) => {
            try {
                const { id } = req.params;
                const { delivery_status } = req.body;

                const allowedStatuses = ["In Transit", "Delivered"];
                if (!delivery_status || !allowedStatuses.includes(delivery_status)) {
                    return res.status(400).json({ message: "Invalid delivery status" });
                }

                const filter = { _id: new ObjectId(id) };

                // Fetch the parcel first to get related info
                const parcel = await parcelsCollection.findOne(filter);
                if (!parcel) {
                    return res.status(404).json({ message: "Parcel not found" });
                }

                // Prepare update document
                const updateDoc = {
                    $set: {
                        delivery_status,
                        updated_at: new Date(),
                    },
                };

                if (delivery_status === "In Transit") {
                    updateDoc.$set.pickup_at = new Date();
                } else if (delivery_status === "Delivered") {
                    updateDoc.$set.delivered_at = new Date();
                }

                // Update the parcel
                await parcelsCollection.updateOne(filter, updateDoc);

                // ================= CREATE NOTIFICATIONS =================
                const notifications = [];
                const adminUsers = await usersCollection.find({ role: "admin" }).toArray();

                if (delivery_status === "In Transit") {
                    // Notify Admin that Rider picked up parcel
                    adminUsers.forEach(admin => {
                        notifications.push({
                            userEmail: admin.email,
                            userType: "admin", // <-- add this
                            message: `Parcel ${parcel.tracking_id} picked up by ${parcel.assigned_rider_name}`,
                            type: "parcel_delivered",
                            is_read: false,
                            created_at: new Date(),
                        });
                    });
                } else if (delivery_status === "Delivered") {
                    // Notify the sender that parcel is delivered
                    notifications.push({
                        userEmail: parcel.created_by, // the sender
                        userType: "user",
                        message: `Your parcel ${parcel.tracking_id} has been delivered`,
                        type: "parcel_delivered",
                        is_read: false,
                        created_at: new Date(),
                    });
                    // Notify Admin that Rider delivered parcel
                    adminUsers.forEach(admin => {
                        notifications.push({
                            userEmail: admin.email,
                            userType: "admin", // <-- add this
                            message: `Parcel ${parcel.tracking_id} delivered by ${parcel.assigned_rider_name}`,
                            type: "parcel_delivered",
                            is_read: false,
                            created_at: new Date(),

                        });
                    });
                }

                if (notifications.length > 0) {
                    await notificationsCollection.insertMany(notifications);
                }

                res.json({
                    success: true,
                    message: `Parcel marked as ${delivery_status} and notifications sent`,
                });
            } catch (error) {
                console.error("Parcel status update error:", error);
                res.status(500).json({ message: "Server error" });
            }
        });


        // rider cash-out
        app.patch("/parcels/:id/cash-out", verifyFBToken, verifyRider, async (req, res) => {
            try {
                const { id } = req.params;
                const parcel = await parcelsCollection.findOne({ _id: new ObjectId(id) });

                if (!parcel) return res.status(404).json({ message: "Parcel not found" });
                if (parcel.delivery_status !== "Delivered")
                    return res.status(400).json({ message: "Parcel not delivered yet" });
                if (parcel.cashout_status === "pending" || parcel.cashout_status === "cashed_out")
                    return res.status(400).json({ message: "Cashout already requested or completed" });

                await parcelsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    {
                        $set: {
                            cashout_status: "pending",
                            requested_cashout_at: new Date(),
                        },
                    }
                );

                // 🔔 Notify admin
                await createNotification({
                    userType: "admin",
                    userEmail: parcel.assigned_rider_email,
                    message: `${parcel.assigned_rider_name} requested a cash-out`,
                    type: "cashout",
                });


                res.json({ success: true, message: "Cash out requested and admin notified" });
            } catch (error) {
                res.status(500).json({ message: "Server error" });
            }
        });


        // tracking api

        // get tracking
        app.get("/tracking/:trackingId", async (req, res) => {
            try {
                const { trackingId } = req.params;

                if (!trackingId) {
                    return res.status(400).json({
                        success: false,
                        message: "Tracking ID is required",
                    });
                }

                const timeline = await trackingsCollection
                    .find({ tracking_id: trackingId })
                    .sort({ updated_at: 1 }) // oldest → latest
                    .toArray();

                res.json({
                    success: true,
                    tracking_id: trackingId,
                    timeline,
                });

            } catch (error) {
                console.error("Tracking fetch error:", error);
                res.status(500).json({
                    success: false,
                    message: "Server error",
                });
            }
        });


        app.post("/tracking", async (req, res) => {
            try {
                const {
                    tracking_id,
                    status,
                    label,
                    updated_by
                } = req.body;

                if (!tracking_id || !status || !label) {
                    return res.status(400).json({ message: "Missing required fields" });
                }

                const trackingDoc = {
                    tracking_id,
                    status,
                    label,
                    updated_by,
                    updated_at: new Date(),
                };

                const result = await trackingsCollection.insertOne(trackingDoc);

                res.json({
                    success: true,
                    insertedId: result.insertedId,
                });
            } catch (error) {
                console.error("Tracking insert error:", error);
                res.status(500).json({ message: "Server error" });
            }
        });


        // riders api

        app.post("/riders", verifyFBToken, async (req, res) => {
            try {
                const rider = req.body;
                const email = rider.email;

                // 🔍 Check if rider already exists
                const existingRider = await ridersCollection.findOne({ email });

                if (existingRider) {
                    return res.status(409).json({
                        success: false,
                        message: "Rider already exists with this email",
                    });
                }

                rider.status = "pending";
                rider.created_at = new Date();

                const result = await ridersCollection.insertOne(rider);

                res.json({
                    success: true,
                    insertedId: result.insertedId,
                });
            } catch (error) {
                console.error("Rider insert error:", error);
                res.status(500).json({
                    success: false,
                    message: "Server error",
                });
            }
        });


        // ✅ GET ALL PENDING RIDERS
        app.get('/riders/pending', verifyFBToken, verifyAdmin, async (req, res) => {
            try {
                const pendingRiders = await ridersCollection
                    .find({ status: 'pending' })
                    .toArray();

                res.send({
                    success: true,
                    count: pendingRiders.length,
                    data: pendingRiders
                });
            } catch (error) {
                res.status(500).send({
                    success: false,
                    message: 'Failed to fetch pending riders',
                    error: error.message
                });
            }
        });
        // ✅ Get ACTIVE riders by district
        app.get("/riders/active", async (req, res) => {
            try {
                const { district } = req.query;

                const query = {
                    status: "active",
                };

                if (district) {
                    query.district = district;
                }

                const riders = await ridersCollection.find(query).toArray();
                res.send(riders);
            } catch (error) {
                res.status(500).json({ message: error.message });
            }
        });

        // PATCH /riders/:id/status
        app.patch("/riders/:id/status", verifyFBToken, verifyAdmin, async (req, res) => {
            try {
                const { id } = req.params;
                const { status, email } = req.body; // expects { status: "active" | "rejected" | "deactivated" }

                // ✅ Validate status
                const allowedStatuses = ["active", "rejected", "deactivated"];
                if (!status || !allowedStatuses.includes(status)) {
                    return res.status(400).json({ message: "Invalid status value" });
                }

                const filter = { _id: new ObjectId(id) };
                const updateDoc = { $set: { status } };

                const result = await ridersCollection.updateOne(filter, updateDoc);

                if (result.matchedCount === 0) {
                    return res.status(404).json({ message: "Rider not found" });
                }

                res.json({
                    message: `Rider status updated to ${status} successfully`,
                    modifiedCount: result.modifiedCount,
                });

                if (status === 'active') {
                    const userQuery = { email }
                    const userUpdatedDoc = {
                        $set: {
                            role: 'rider'
                        }
                    };
                    const roleResult = await usersCollection.updateOne(userQuery, userUpdatedDoc)
                    console.log(roleResult.modifiedCount)
                }
            } catch (error) {
                console.error(error);
                res.status(500).json({ message: "Server error" });
            }
        });


        // Get all active riders
        app.get('/riders/active', verifyFBToken, verifyAdmin, async (req, res) => {
            try {
                const activeRiders = await ridersCollection
                    .find({ status: 'active' }) // only active riders
                    .toArray();
                res.send(activeRiders); // send array directly
            } catch (error) {
                console.error(error);
                res.status(500).json({ message: 'Server error' });
            }
        });

        //get all riders pending parcels

        app.get("/rider/parcels", verifyFBToken, async (req, res) => {
            try {
                const riderEmail = req.query.email;

                // security check
                if (req.decoded.email !== riderEmail) {
                    return res.status(403).send({ message: "Forbidden access" });
                }

                const query = {
                    assigned_rider_email: riderEmail,
                    delivery_status: { $in: ["Rider Assigned", "In Transit"] },
                };

                const parcels = await parcelsCollection
                    .find(query)
                    .sort({ created_at: -1 }) // latest first
                    .toArray();

                res.send(parcels);
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Server error" });
            }
        });

        //get all riders delivered parcels
        app.get(
            "/rider/completed-parcels",
            verifyFBToken,
            verifyRider,
            async (req, res) => {
                try {
                    const riderEmail = req.decoded.email;

                    const query = {
                        assigned_rider_email: riderEmail,
                        delivery_status: {
                            $in: ["Delivered", "Regional Hub Delivered"],
                        },
                    };

                    const completedParcels = await parcelsCollection
                        .find(query)
                        .sort({ delivered_at: -1 }) // latest delivery first
                        .toArray();

                    res.json({
                        success: true,
                        data: completedParcels,
                    });
                } catch (error) {
                    console.error("Completed parcels error:", error);
                    res.status(500).json({
                        success: false,
                        message: "Server error",
                    });
                }
            }
        );

        // admin GET /parcels?cashout_status=pending
        app.get("/admin/payouts", verifyFBToken, verifyAdmin, async (req, res) => {
            try {
                const { cashout_status } = req.query; // optional filter
                const filter = {};

                if (cashout_status) filter.cashout_status = cashout_status;

                const parcels = await parcelsCollection
                    .find(filter)
                    .sort({ created_at: -1 })
                    .toArray();

                res.json({ success: true, data: parcels });
            } catch (error) {
                console.error("Fetching payouts error:", error);
                res.status(500).json({ success: false, message: "Server error" });
            }
        });

        // Admin approves cash-out API

        app.patch("/parcels/:id/approve-cashout", verifyFBToken, verifyAdmin, async (req, res) => {
            try {
                const { id } = req.params;
                const parcel = await parcelsCollection.findOne({ _id: new ObjectId(id) });

                if (!parcel) return res.status(404).json({ message: "Parcel not found" });
                if (parcel.cashout_status !== "pending")
                    return res.status(400).json({ message: "Cashout is not pending" });

                await parcelsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    {
                        $set: {
                            cashout_status: "cashed_out",
                            approved_cashout_at: new Date(),
                        },
                    }
                );

                // 🔔 Notify rider
                await createNotification({
                    userType: "rider",
                    userEmail: parcel.assigned_rider_email,
                    message: "Your cash-out request has been approved",
                    type: "cashout",
                });

                res.json({ success: true, message: "Cashout approved and rider notified" });
            } catch (error) {
                res.status(500).json({ message: "Server error" });
            }
        });

        // dashboard api

        // admin dashboard
        app.get("/admin/dashboard", verifyFBToken, async (req, res) => {
            try {
                // 🔐 Admin check
                const admin = await usersCollection.findOne(
                    { email: req.decoded.email },
                    { projection: { role: 1 } }
                );

                if (!admin || admin.role !== "admin") {
                    return res.status(403).json({ message: "Admin access only" });
                }

                // ===== PARCEL STATS =====
                const parcelStats = await parcelsCollection.aggregate([
                    {
                        $facet: {
                            totalParcels: [{ $count: "count" }],

                            inTransit: [
                                { $match: { delivery_status: "In Transit" } },
                                { $count: "count" }
                            ],

                            delivered: [
                                { $match: { delivery_status: "Delivered" } },
                                { $count: "count" }
                            ],

                            pendingPayment: [
                                { $match: { payment_status: "pending" } },
                                { $count: "count" }
                            ],

                            totalRevenue: [
                                { $match: { payment_status: "paid" } },
                                { $group: { _id: null, total: { $sum: "$deliveryCost" } } }
                            ],

                            // 📊 Chart 1: Parcels by Status
                            parcelsByStatus: [
                                {
                                    $group: {
                                        _id: "$delivery_status",
                                        count: { $sum: 1 }
                                    }
                                }
                            ],

                            // 📊 Chart 2: Parcels per Rider
                            parcelsPerRider: [
                                { $match: { assigned_rider_name: { $exists: true } } },
                                {
                                    $group: {
                                        _id: "$assigned_rider_name",
                                        count: { $sum: 1 }
                                    }
                                }
                            ]
                        }
                    }
                ]).toArray();

                // ===== USER STATS =====
                const totalUsers = await usersCollection.countDocuments({ role: "user" });
                const totalRiders = await usersCollection.countDocuments({ role: "rider" });

                res.json({
                    ...parcelStats[0],
                    totalUsers,
                    totalRiders
                });

            } catch (error) {
                console.error("Admin dashboard error:", error);
                res.status(500).json({ message: "Server error" });
            }
        });

        // rider dashboard

        app.get("/rider/dashboard", verifyFBToken, verifyRider, async (req, res) => {
            try {
                const email = req.decoded.email;

                // Total assigned parcels
                const totalParcels = await parcelsCollection.countDocuments({ assigned_rider_email: email });

                // Parcels in transit
                const inTransit = await parcelsCollection.countDocuments({
                    assigned_rider_email: email,
                    delivery_status: "In Transit"
                });

                // Parcels delivered
                const delivered = await parcelsCollection.countDocuments({
                    assigned_rider_email: email,
                    delivery_status: "Delivered"
                });

                // Pending cash-out requests
                const pendingCashOut = await parcelsCollection.countDocuments({
                    assigned_rider_email: email,
                    cashout_status: "pending"
                });

                // Bar chart: In Transit vs Delivered
                const statusAggregation = await parcelsCollection.aggregate([
                    { $match: { assigned_rider_email: email } },
                    { $group: { _id: "$delivery_status", count: { $sum: 1 } } }
                ]).toArray();

                // Pie chart: Cash-out requested vs cashed out
                const cashOutAggregation = await parcelsCollection.aggregate([
                    { $match: { assigned_rider_email: email } },
                    { $group: { _id: "$cashout_status", count: { $sum: 1 } } }
                ]).toArray();

                res.json({
                    totalParcels,
                    inTransit,
                    delivered,
                    pendingCashOut,
                    statusAggregation,
                    cashOutAggregation
                });

            } catch (error) {
                console.error("Rider dashboard error:", error);
                res.status(500).json({ message: "Server error" });
            }
        });



        // payment api

        app.post('/create-payment-intent', async (req, res) => {
            try {
                const { amount } = req.body;
                if (!amount || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });

                const paymentIntent = await stripe.paymentIntents.create({
                    amount: amount * 100, // in cents
                    currency: 'usd',      // change to 'bdt' if using Taka
                });

                res.json({ clientSecret: paymentIntent.client_secret });
            } catch (err) {
                console.error(err);
                res.status(500).json({ error: 'Stripe Error' });
            }
        });

        app.get('/payments', verifyFBToken, async (req, res) => {

            try {
                const userEmail = req.query.email;
                console.log('decoded', req.decoded)
                if (req.decoded.email !== userEmail) {
                    return res.status(403).send({ massage: 'Forbidden access' })
                }
                const query = userEmail ? { email: userEmail } : {};

                const payments = await paymentsCollection
                    .find(query)
                    .sort({ createdAt: -1 }) // latest first
                    .toArray();

                res.json(payments);
            } catch (error) {
                console.error("Error fetching payments:", error);
                res.status(500).json({ message: error.message });
            }
        });

        app.post('/payments', async (req, res) => {
            try {
                const { parcelId, amount, transactionId, email } = req.body;

                if (!parcelId || !amount || !transactionId)
                    return res.status(400).json({ error: 'Missing data' });

                const parcel = await parcelsCollection.findOne({ _id: new ObjectId(parcelId) });
                if (!parcel) return res.status(404).json({ error: 'Parcel not found' });

                // Update parcel payment status
                await parcelsCollection.updateOne(
                    { _id: new ObjectId(parcelId) },
                    { $set: { payment_status: 'paid', transactionId } }
                );

                // Save payment record
                await paymentsCollection.insertOne({
                    parcelId: new ObjectId(parcelId),
                    amount,
                    transactionId,
                    email,
                    createdAtString: new Date().toISOString(),
                    createdAt: new Date(),
                });

                res.json({ success: true });
            } catch (err) {
                console.error(err);
                res.status(500).json({ error: 'Server error' });
            }
        });

        // notification api endpoints

        // GET /notifications
        // Fetch notifications for the logged-in user, dynamically getting their role
        app.get("/notifications", verifyFBToken, async (req, res) => {
            try {
                // 1️⃣ Get the logged-in user's email from the decoded Firebase token
                const email = req.decoded.email;

                if (!email) {
                    return res.status(401).json({ message: "Unauthorized" });
                }

                // 2️⃣ Fetch the user's role from the users collection
                const user = await usersCollection.findOne(
                    { email },
                    { projection: { role: 1 } }
                );

                const role = user?.role || "user"; // Default to 'user' if role not set

                // 3️⃣ Build query for notifications
                // Show notifications for the user type, and optionally only for this user's email
                const query = {
                    userType: role, // e.g., "user", "rider", "admin"
                    $or: [
                        { userEmail: email },  // user-specific notifications
                        { userEmail: null },   // general notifications for the role
                    ],
                };

                // 4️⃣ Fetch notifications from DB, newest first
                const notifications = await notificationsCollection
                    .find(query)
                    .sort({ created_at: -1 })
                    .toArray();

                // 5️⃣ Send response
                res.json({ data: notifications });
            } catch (err) {
                console.error("Error fetching notifications:", err);
                res.status(500).json({ message: "Server error" });
            }
        });


        app.patch("/notifications/:id/read", verifyFBToken, async (req, res) => {
            try {
                const { id } = req.params;
                const result = await notificationsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { is_read: true } }
                );

                if (result.modifiedCount > 0) {
                    res.json({ success: true });
                } else {
                    res.json({ success: false, message: "Notification not found" });
                }
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Server error" });
            }
        });

        app.delete("/notifications/:id", verifyFBToken, async (req, res) => {
            try {
                const { id } = req.params;
                const result = await notificationsCollection.deleteOne({
                    _id: new ObjectId(id),
                });

                if (result.deletedCount > 0) {
                    res.json({ success: true });
                } else {
                    res.json({ success: false, message: "Notification not found" });
                }
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Server error" });
            }
        });


        app.listen(PORT, () => {
            console.log(`🚀 Server is running on port ${PORT}`);
        });

        // Graceful shutdown handler
        process.on("SIGINT", async () => {
            console.log("Shutting down gracefully...");
            await client.close();
            process.exit(0);
        });

    } catch (error) {
        console.error("❌ Failed to start server:", error);
        process.exit(1);
    }
}

// Start everything
startServer();



