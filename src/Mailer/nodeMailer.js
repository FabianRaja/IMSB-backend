import { createTransport } from "nodemailer";

//creating transport to send mail
export const transport=createTransport({
    service:"gmail",
    auth:{
        user:"fabianrajafernandofsd@gmail.com",
        pass:"ougk njwl zspv fyav"
    },
})