<?php

namespace App\Http\Controllers;

use App\Http\Requests\RegisterRequest;
use Illuminate\Http\Request;
use App\Http\Resources\UserResource;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(RegisterRequest $request)
    {
        $request->merge([
            'password' => bcrypt($request->password),
        ]);
        $user = User::create($request->validated());

        $success['token'] = $user->createToken('chat-app')->plainTextToken;
        $success['user'] = new UserResource($user);

        return response()->json([
            'user' => $success['user'],
            'token' => $success['token'],
        ],201);
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'errors' => $validator->errors(),
            ], 422);
        }

        if(!Auth::attempt($validator->validated())) {
            return response()->json([
                'message' => 'Invalid credentials',
            ], 401);
        }

        $user = Auth::user();

        $success['token'] = $user->createToken('chat-app')->plainTextToken;
        $success['user'] = new UserResource($user);

        return response()->json([
            'user' => $success['user'],
            'token' => $success['token'],
        ],200);
    }

    public function logout()
    {
        Auth::user()->currentAccessToken()->delete();

        return response()->json([
            'message' => 'Logged out',
        ],200);
    }
}
