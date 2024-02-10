import exLogo from "../image/shoe_6.png";
import {useNavigate} from "react-router-dom";

export default function HeroBanner(props){
    let bannerData = props.bannerData;
    let navigate = useNavigate();

    let detailHeroBannerHandler = (data)=>{
            navigate(`/products/${data.banner?._id}`);
    }
    return (


                <div className="hero-banner-container">
                    <div >

                    <p className="beats-solo">
                        {bannerData[0]?.LargeText1}
                    </p>
                <h3 >{bannerData[0]?.MidText}</h3>
                <h1 style={{fontStyle : "bold" , fontSize : "115px"}}>
                    {bannerData[0]?.product}
                </h1>
                <img src={bannerData[0]?.image} alt="headphone"
                     className="hero-banner-image"
                     width={200}
                     height={200}
                     style={{cursor : "pointer"}}
                     onClick={()=> detailHeroBannerHandler(bannerData[0])}
                />
                    </div>

                <div >
                    <button className="button" type="button" onClick={()=> detailHeroBannerHandler(bannerData[0])}>{bannerData[0]?.ButtonText}</button>

                    <div className="desc">
                        <h5>Description</h5>
                        <p>{bannerData[0]?.Desc}</p>
                    </div>
                </div>

                </div>


    )
}