import Swal from "sweetalert2";


export default function SwalUIPage(){
    return (
        <div>
            {
                Swal.fire({
                    title : 'Logout Account',
                    text : 'Are you sure to logout your account ?',
                    icon : 'warning',
                    showCancelButton : true,
                    confirmButtonText : 'LogOut',
                    cancelButtonText : 'Cancel'
                }).then(result=>{
                    if(result.isConfirmed){
                        Swal.fire({
                                title : 'LogOut!',
                                html : 'Success LogOut !',
                                icon : 'success'
                            }
                        )
                        //code
                    }
                })
            }

        </div>
    )
}