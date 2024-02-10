
import {useNavigate} from "react-router-dom";

export default function FooterBanner(props){
    let footerBannerData = props.footerBannerData;
    let navigate = useNavigate();

    let handleShop = (data)=>{
        console.log("data => ",data);
        navigate(`/products/${data.banner._id}`);
    }
    return (
        <div className="footer-banner-container">
            <div className="banner-desc">
                <div className="left">
                    <p>{footerBannerData[1]?.Discount} OFF</p>
                    <h3 style={{fontSize : "40px"}}>{footerBannerData[1]?.LargeText1}</h3>
                    <h3 style={{fontSize : "60px"}}>{footerBannerData[1]?.product}</h3>
                    <p>{footerBannerData[1]?.saleTime}</p>
                </div>
                <div className="right">
                    <p>{footerBannerData[1]?.SmallText}</p>
                    <h3>{footerBannerData[1]?.MidText}</h3>
                    <p>{footerBannerData[1]?.Desc}</p>

                    <button type="button" onClick={()=> handleShop(footerBannerData[1])}>{footerBannerData[1]?.ButtonText}</button>

                    <img src={footerBannerData[1]?.image} alt="no photo" className="footer-banner-image" width={300} height={300}/>

                </div>
            </div>
        </div>
    )
}