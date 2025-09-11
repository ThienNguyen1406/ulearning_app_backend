<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Carbon;
use App\Models\User;

class UserController extends Controller
{
    /**
     * Đăng ký user mới (email & password)
     */
    public function registerUser(Request $request)
    {
       try{
         $validateUser = Validator::make($request->all(), [

           'avatar' => 'required',
            'type' => 'required',
            'open_id' => 'required',
            'name'     => 'required',
            'email'    => 'required',
            'password' => 'required|min:6',
        ]);

        if ($validateUser->fails()) {
            return response()->json([
                'status'  => false,
                'message' => 'Validation error',
                'errors'  => $validateUser->errors(),
            ], 401);
        }

        //validaeted will have all user filed values
        //wee can save in the db
        $validated = $validateUser-> validated();

        $map=[];
        //email, google, phone, facebook, apple
        $map['type'] = $validated['type'];
        $map['open_id'] = $validated['open_id'];

        $user = User::where($map)->first();

        //whether user has already logged in or not
        //emty means does not exist
        //then save the user in the database for first time
        if(empty($user -> id)){
            //this certain user has never been in pout db
            //our job is to assign the user in the db
            //this toekn is user id
            $validated["token"] = md5(uniqid().rand(10000,99999 ));
            //user first time created
            $validated['created_at'] = Carbon::now();
            //encript password
            //$validated['password'] = Hash::make($validated['password']);
            //return id of row after saving
            $userID= User :: insertGetId($validated);
            // user's all in formation
            $userInfo = User::where('id', '=', $userID) -> first();

            //create access token
           $accessToken = $userInfo->createToken(uniqid())->plainTextToken;

            $userInfo -> access_token = $accessToken;
            User:: where('id', '=', $userID) -> update(['access_token'=>$accessToken]);

             return response()->json([
                'code'  => 200,
                'msg' => 'User Created Successfuly',
                'data'  => $userInfo,
            ], 200);

        }
        
        //user previously has logged in
        $accessToken = $user->createToken(uniqid())->plainTextToken;
        $user->access_token = $accessToken;
        User:: where('open_id', '=', $validated['open_id']) -> update(['access_token'=>$accessToken]);
      
        return response()->json([
            'code'  => 200,
            'msg' => 'User logged Successfuly',
            'data'  => $user,
            // 'user'    => $user
        ], 200);
       }catch(\Throwable $th){
         return response()->json([
            'status'  => false,
            'message' => $th->getMessage(),
        ], 500);
       };
    }

    /**
     * Đăng nhập user (email & password)
     */
    public function loginUser(Request $request)
    {
        try{
            $validateUser = Validator::make($request->all(), [
            'email'    => 'required|email',
            'password' => 'required',
        ]);

        if ($validateUser->fails()) {
            return response()->json([
                'status'  => false,
                'message' => 'Validation error',
                'errors'  => $validateUser->errors(),
            ], 422);
        }

        if (!Auth::attempt($request->only('email', 'password'))) {
            return response()->json([
                'status'  => false,
                'message' => 'Email or password is incorrect',
            ], 401);
        }

        $user  = User::where('email', $request->email)->first();

        return response()->json([
            'status'  => true,
            'message' => 'User logged in successfully',
            'token'   => $user->createToken('API TOKEN')->plainTextToken,
        ], 200);
        }catch(\Throwable $th){
         return response()->json([
            'status'  => false,
            'message' => $th->getMessage(),
        ], 500);
       };
    }
    
}


