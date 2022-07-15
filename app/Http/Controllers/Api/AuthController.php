<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Api\BaseController as BaseController;
use App\Models\User;
use Validator;
use bcrypt;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        if(Auth::attempt(['email' => $request->email, 'password' => $request->password])){ 
            $auth = Auth::user(); 
            $success['token'] =  $auth->createToken('LaravelSanctumAuth')->plainTextToken; 
            $success['name'] =  $auth->name;
   
            $res = [
                'success' => true,
                'data'    => $success,
                'message' => 'User logged-in!',
            ];
            return response()->json($res, 200);
        } 
        else{ 
            $res = [
                'success' => false,
                'message' => 'Unauthorised.',
                'data' => ['error'=>'Unauthorised']
            ];
            return response()->json($res, 404);
        } 
    }


    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|unique:users|email',
            'password' => 'required',
            'confirm_password' => 'required|same:password',
            'phone' => 'required',

        ]);
   
        if($validator->fails()){ 
            $res = [
                'success' => false,
                'message' => $validator->errors(),
            ];
            return response()->json($res, 404);     
        }
   
        $input = $request->all();
        $input['password'] = bcrypt($input['password']);
        $user = User::create($input);
        $success['token'] =  $user->createToken('LaravelSanctumAuth')->plainTextToken;
        $success['name'] =  $user->name;

        $res = [
            'success' => true,
            'data'    => $success,
            'message' => 'User successfully registered!',
        ];
        return response()->json($res, 200);
    }

    public function logout(){
        $user = request()->user();

        $user->tokens()->where('id', $user->currentAccessToken()->id)->delete();
        Auth::user()->tokens->each(function($token, $key) {
            $token->delete();
        });
        
        return response()->json(['status' => 200, 'message' => 'Successfully Logged out.']);
    }
}
