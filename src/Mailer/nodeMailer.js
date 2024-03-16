import { createTransport } from "nodemailer";

//creating transport to send mail
export const transport=createTransport({
    service:"gmail",
    auth:{
        user:"fullstackpurpose@gmail.com",
        pass:"dmuh pnrp ajxi pdtk"
    },
})