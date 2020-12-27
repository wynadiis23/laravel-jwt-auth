<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    /**
     * tutorial mengikuti
     * 
     * link : https://www.positronx.io/laravel-jwt-authentication-tutorial-user-login-signup-api/
     * 
     */
    /**
     * fungsi akan melalui middleware auth api kecuali utnuk proses login dan register
     * sehingga fungsi dalam except tidak perlu token
     */
    public function __construct(){
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }
    /**
     * proses request, ketika gagal
     * 1. akan dikambalikan dengan error 422
     * 2. ketika token tidak sama, akan dikembalikan error 401
     * 
     * proses lanjut ketika user tidka punya token
     * 1. memanggil fungsi createNewToken
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()){
            return response()->json($validator->errors(), 422);
        }

        if(!$token = auth()->attempt($validator->validated())){
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->createNewToken($token);
    }

    /** 
     * fungsi register biasa, ketika error validator, akan dikembalikan dengan 400
     * perli isi semua form dg sesuai
     * */ 
    public function register(Request $request)
    {   
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|between:2,100',
            'email' => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|confirmed|min:6',
        ]);

        if($validator->fails()){
            return response()->json($validator->errors()->toJson(), 400);
        }

        $user = User::create(array_merge(
            $validator->validated(),
            ['password' => bcrypt($request->password)]
        ));

        return response()->json([
            'message' => 'User successfully registered',
            'user' => $user
        ], 200);
    }

    /**
     * logout kemudian token dari localstorage dihapus 
     */
    public function logout()
    {
        auth()->logout();

        return response()->json([
            'message' => 'User successfully signed out'
        ]);
    }

    /**
     * refresh token dengan memanggil fungsi create token
     * namun hanya bisa ketika masih login 
     */
    public function refresh()
    {
        return $this->createNewToken(auth()->refresh());
    }

    public function userProfile()
    {
        return response()->json(auth()->user());
    }

    /**
     * 
     */
    protected function createNewToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user()
        ]);
    }

    public function userList()
    {
        return response()->json(auth()->user()->all());
    }
}
