import {loadStripe} from '@stripe/stripe-js';

let stripePromise ;

const getStripe = ()=>{
    if(!stripePromise){
        stripePromise = loadStripe(process.env.STRIPE_PUBLIC_KEY);
    }
    return stripePromise;
}

/** handleCheckout
 *async ()=>{
 *     const stripe = await getStripe();
 *     const response = await fetch('/aip/stripe' , {
 *         method : 'POST',
 *         headers : {
 *             'Content-type' : 'application/json',
 *         },
 *         body :  JSON.stringify(cartItems),
 *     });
 *
 *     if(response.statusCode === 500) return ;
 *
 *     const data = await response.json();
 *     toast.loading('Redirecting.............');
 *
 *     stripe.redirectToCheckout({sessionId : data.id});
 * }
 *
 * */

export default getStripe;