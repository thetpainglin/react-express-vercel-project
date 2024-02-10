const strike = require('stripe')(process.env.STRIKE_SECRET_KEY);

export default async function handler(req , res ){
    if(req.method === 'POST'){
        try{
            //Create checkout sessions from body params .
            let params = {
                submit_type : 'pay',
                mode : 'payment',
                payment_method_types : ['card'],
                billing_address_collection : 'auto',
                shipping_options : [
                    //Shipping Rate in stripe.com
                    {shipping_rate : ''}
                ],
                line_items : req.body.cartItems.map((item) => {
                    const img = item.image[0].asset._ref;
                }),

                success_url : `${req.headers.origin}/?success=true`,
                cancel_url : `${req.headers.origin}/?canceled=true`,
            };
            const session = await strike.checkout.sessions.create(params);
            res.redirect(303,session.url);
        }catch (e){
            res.status(e.statusCode || 500).json(e.message);
        }
    } else {
        res.setHeader('Allow','POST');
        res.status(405).end("Method Not Allowed ! ");
    }
}