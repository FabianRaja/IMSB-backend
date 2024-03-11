import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken"
import addingUsers, { activation, addingProduct, findUsers, findingUsers, forgotToken, updatingPassword } from "../Controllers/index.js";
import { generateExpiryToken, generateToken, isAuthorized } from "../Authorization/auth.js";
import { transport } from "../Mailer/nodeMailer.js";

//initializing router
const router=express.Router();

//user registration
router.post("/register",async(req,res)=>{
    try {
        //finding if user already registered with the emailid
        const findUser=await findingUsers(req.body.email);
        if(findUser.length>=1){
            return res.status(400).json({message:"User email already registered"});
        }else{
            //encrypting user password
            const salt=await bcrypt.genSalt(10);
            const hashedPassword=await bcrypt.hash(req.body.password,salt);
            //creating object with user details
            const data={
                email:req.body.email,
                name:req.body.name,
                password:hashedPassword,
                status:"InActive",
                token:"",
                data:[]
            }
            //adding user to the db
            const registeringUser=await addingUsers(data);
            //sending mail to activate account
            const link=`https://makeasyurl.netlify.app/activation/${registeringUser[0]._id}`
            //composing mail
            const composingMail={
                from:"fullstackpurpose@gmail.com",
                to:registeringUser[0].email,
                subject:"Account Activation Link",
                html:`<a href=${link}><button style="background:violet;
                color:black;
                height:50px;
                width:150px;
                border:none;
                border-radius:15px;
                font-weight:bolder;
                ">Click to Activate Account</button></a>
                `
            }
            //creating transport to send mail
            transport.sendMail(composingMail,(error,info)=>{
                if(error){
                    console.log(error)
                }else{
                    console.log("mail sent")
                }
            })
            return res.status(200).json({message:"Activation link sent to Mail",data:registeringUser})
        }
    } catch (error) {
        console.log(error)
        res.status(500).json({message:"Registration failed"})
    }
})
//account activation
router.get("/activation/:id",async(req,res)=>{
    try {
        //finding user and updating account status
         const activateUser=await activation(req.params.id);
         if(!activateUser){
            return res.status(400).json({message:"Invalid link or Link Expired"});
         }else{
            return res.status(200).json({message:"Activation Successfull"})
         }
        }
   catch (error) {
        console.log(error)
        res.status(500).json({message:"Account activation failed"})
    }
})
//login User
router.post("/login",async(req,res)=>{
    try {
        //checking is user email is registered 
        const checkUser=await findingUsers(req.body.email);
        if(checkUser.length===0){
            return res.status(400).json({message:"Invalid email"});
        }else{ 
            //validating password with email
            const validatingPassword=await bcrypt.compare(req.body.password,checkUser[0].password);
            if(validatingPassword){
                //checking if account is active or not
                if(checkUser[0].status==="Active"){
                    //token is generated and passed as response
                    const token=generateToken(checkUser[0]._id);
                    return res.status(200).json({message:"login success",token,data:checkUser})
                }else{
                    //if account is not active
                     //sending mail to activate account
                    const link=`https://makeasyurl.netlify.app/activation/${checkUser[0]._id}`
                    //composing mail
                    const composingMail={
                        from:"fullstackpurpose@gmail.com",
                        to:checkUser[0].email,
                        subject:"Account Activation Link",
                        html:`<a href=${link}><button style="background:violet;
                        color:black;
                        height:50px;
                        width:150px;
                        border:none;
                        border-radius:15px;
                        font-weight:bolder;
                        ">Click to Activate Account</button></a>
                        `
                    }
                    //creating transport to send mail
                    transport.sendMail(composingMail,(error,info)=>{
                        if(error){
                            console.log(error)
                        }else{
                            console.log("mail sent")
                        }
                    })
                    return res.status(200).json({message:"Account is Not Active, Activation Link sent to mail"})
                }
            }else{
                return res.status(200).json({message:"Invalid Password"})
            }  
        }
}catch (error) {
        console.log(error)
        res.status(500).json({message:"Login User Failed"})
    }
})
//forgot password
router.post("/forgot",async(req,res)=>{
    try {
        //checking user email is registered or not
        const findUser=await findingUsers(req.body.email);
        if(findUser.length<1){
            return res.status(400).json({message:"Invalid Email address"})
        }else{
            //creating expiry token
            const token=await generateExpiryToken(findUser[0]._id);
            //adding token to the database
            const setToken=await forgotToken(findUser[0]._id,token);
             //sending mail to reset password
             const link=`https://makeasyurl.netlify.app/reset/${findUser[0]._id}`
             //composing mail
             const composingMail={
                 from:"fullstackpurpose@gmail.com",
                 to:findUser[0].email,
                 subject:"Password Reset Link",
                 html:`<a href=${link}><button style="background:violet;
                 color:black;
                 height:50px;
                 width:150px;
                 border:none;
                 border-radius:15px;
                 font-weight:bolder;
                 ">Click to Reset Password</button></a>`
             }
             //creating transport to send mail
             transport.sendMail(composingMail,(error,info)=>{
                 if(error){
                     console.log(error)
                 }else{
                     console.log("mail sent")
                 }
             })
             return res.status(200).json({message:"Reset Link sent to mail"});
        }
        }
   catch (error) {
        console.log(error)
        res.status(500).json({message:"Error forgot Password"})
    }
})
//reset password
router.post("/reset/:id",async(req,res)=>{
    try {
          //finding user
          const getUser=await findUsers(req.params.id);
          //verifying token
          const verify=jwt.verify(getUser[0].token,process.env.secret_key);
          //encrypting user password
          const salt=await bcrypt.genSalt(10);
          const hashedPassword=await bcrypt.hash(req.body.password,salt);
          //updating password
          const updating=await updatingPassword(getUser[0]._id,hashedPassword);
          return res.status(200).json({message:"Password Reset Successfull"});
        }
   catch (error) {
        console.log(error)
        res.status(500).json({message:"Reset Link Expired"})
    }
})

//add product
router.post("/addProduct",isAuthorized,async(req,res)=>{
    try {
          const findUser=await findUsers(req.body.id);
          //checking if theres already a product with the same name
          const checkArray=[];
          const checkingData=findUser[0].data;
          checkingData.find((value,index)=>{
               if(req.body.productName===value.productName){
                checkArray.push("exits");
                return true;
               }
          })

          //if theres no product with the same name it will add product as a new one or else it will update the quantity and price alone
          if(checkArray.length<=0){
            //creating a new object with the details
            const newData={
                productName:req.body.productName,
                productQuantity:req.body.productQuantity,
                productPrice:req.body.productPrice
              }
              const data=(findUser[0].data).concat(newData);
              const findUserById=await addingProduct(findUser[0]._id,data);
              return res.status(200).json({message:"Adding Product Successfull"});
          }else{
             //finding the object data with the same product name and updating the object details
             checkingData.find((value,index)=>{
                if(req.body.productName===value.productName){
                    checkingData[index]={productName:value.productName,productQuantity:req.body.productQuantity+value.productQuantity,productPrice:req.body.productPrice};
                    return true;  
                }
             });
             const updateData=await addingProduct(findUser[0]._id,checkingData)
             return res.status(200).json({message:"Adding Product Successful"})
          } 
        }
   catch (error) {
        console.log(error)
        res.status(500).json({message:"Error adding product"})
    }
});

//update product
router.post("/editProduct",isAuthorized,async(req,res)=>{
    try {
        const findUser=await findUsers(req.body.id);
        const data=findUser[0].data;
        //filtering the data to be updated and adding the updated object as a new data into the filteredData
        const filteredData=data.filter((value,index)=>value.productName!=req.body.oldProductName);
        const newData={
            productName:req.body.productName,
            productQuantity:req.body.productQuantity,
            productPrice:req.body.productPrice
        }
        filteredData.push(newData);
        console.log(filteredData);
        const updatingData=await addingProduct(findUser[0]._id,filteredData)
          return res.status(200).json({message:"Product Updated Successfull"});
        }
   catch (error) {
        console.log(error)
        res.status(500).json({message:"Error editing product"})
    }
})

//delete product
router.post("/deleteProduct",isAuthorized,async(req,res)=>{
    try {
          const findUser=await findUsers(req.body.id);
          const data=findUser[0].data;
          //filtering data and delete the object
          const filteredData=data.filter((value,index)=>value.productName!=req.body.productName);
          const updatingData=await addingProduct(findUser[0]._id,filteredData)
          return res.status(200).json({message:"Product Deleted Successfull"});
        }
   catch (error) {
        console.log(error)
        res.status(500).json({message:"Error deleting product"})
    }
})

//get all product
router.post("/allProduct",isAuthorized,async(req,res)=>{
    try {
        //getting all product details by the unique user id
          const findingUser=await findUsers(req.body.id);
          return res.status(200).json({message:"all product fetched Successfully",data:findingUser[0].data});
        }
   catch (error) {
        console.log(error)
        res.status(500).json({message:"Error getting all product"})
    }
})

//product bill quanitity decrement
router.post("/billProduct",isAuthorized,async(req,res)=>{
    try {
          const findingUser=await findUsers(req.body.id);
          const originalData=findingUser[0].data;
          const billData=req.body.billData;
          //reducing the product quantity after billing by finding the productName and updating the fields
          billData.map((value,index)=>{
          originalData.find((value1,index1)=>{
                if(value1.productName===value.productName){
                    originalData[index1]={productName:value1.productName,productQuantity:value1.productQuantity-value.productQuantity,productPrice:value1.productPrice};
                    return true;//to stop search process
                }
            })
      
          })
            
         const updatingProduct=await addingProduct(req.body.id,originalData)

       res.status(200).json({message:"bill processed Successfully"});
        }
   catch (error) {
        console.log(error)
        res.status(500).json({message:"Error processing product bill"})
    }
})


export const Router=router;