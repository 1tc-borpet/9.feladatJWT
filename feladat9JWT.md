# 9.feladat — API átállítása JWT tokenes autentikációra (tymon/jwt-auth)

Ez a dokumentáció leírja, JWT-alapú Bearer tokenes autentikációra átállítani.


Base URL
- Lokálisan: `http://127.0.0.1:8000/api`

Áttekintés
- A projekt jelenleg Laravel Sanctum + personal access token logikát használja (User modellban HasApiTokens, `auth:sanctum` middleware a routes/api.php-ban).

Telepítés és alapbeállítások
1) Csomag telepítése:
```bash
composer require tymon/jwt-auth
```

2) Konfiguráció publikálása és secret generálása:
```bash
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
php artisan jwt:secret
```
- Az utóbbi parancs létrehozza a `JWT_SECRET` értéket a `.env` fájlban.

3) Cache frissítése:
```bash
php artisan config:clear
php artisan config:cache
```

Megjegyzés: Ha a projektben korábban szerepeltek Sanctum-specifikus táblák/migrációk (pl. `personal_access_tokens`), ezek nem jelentenek problémát — a jwt-auth stateless megoldás, nem használja ezeket a táblákat. Ha a projektben a HasApiTokens trait-et használod más célra, döntsd el, megtartod-e vagy eltávolítod.

Fájlmódosítások — példák (másold be a tényleges projektbe)

1) app/Models/User.php
- Implementáld a JWTSubject interfészt, add meg a két kötelező metódust, és hagyd vagy távolítsd el a HasApiTokens trait-et (ha nem használod Sanctum-ot tovább, el is távolíthatod).

Példa (javított User.php részlet):
```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
// use Laravel\Sanctum\HasApiTokens; // opcionális: eltávolítható, ha nem használod Sanctum-ot
use Tymon\JWTAuth\Contracts\JWTSubject;

class User extends Authenticatable implements JWTSubject
{
    use HasFactory, Notifiable;

    protected $fillable = [
        'name',
        'email',
        'password',
        'profile_picture',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    // kapcsolatok (posts, likes) maradnak...
    public function posts()
    {
        return $this->hasMany(Post::class);
    }

    public function likes()
    {
        return $this->hasMany(Like::class);
    }

    // JWTSubject interfész metódusok
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims(): array
    {
        return [];
    }
}
```

2) config/auth.php
- Add hozzá vagy módosítsd az `api` guard-ot `jwt` driver-rel:

Részlet példa:
```php
'defaults' => [
    'guard' => env('AUTH_GUARD', 'web'),
    'passwords' => env('AUTH_PASSWORD_BROKER', 'users'),
],

'guards' => [
    'web' => [
        'driver' => 'session',
        'provider' => 'users',
    ],

    'api' => [
        'driver' => 'jwt',
        'provider' => 'users',
    ],
],
```

3) routes/api.php
- Cseréld a védett csoport middleware-ét `auth:sanctum` → `auth:api`.

Példa (teljes routes/api.php a repo alapján, módosított middleware-el):
```php
<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\PostController;
use App\Http\Controllers\LikeController;

// Public routes
Route::get('/ping', function () {
    return response()->json(['message' => 'API works!'], 200);
});

Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);

// Protected routes (JWT Bearer required)
Route::middleware('auth:api')->group(function () {
    // Auth
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::get('/users/me', [AuthController::class, 'me']);

    // Posts
    Route::get('/posts', [PostController::class, 'index']);
    Route::get('/posts/{id}', [PostController::class, 'show']);
    Route::post('/posts', [PostController::class, 'store']);
    Route::put('/posts/{id}', [PostController::class, 'update']);
    Route::delete('/posts/{id}', [PostController::class, 'destroy']);
    Route::get('/users/{id}/posts', [PostController::class, 'userPosts']);

    // Likes
    Route::post('/posts/{id}/like', [LikeController::class, 'like']);
    Route::delete('/posts/{id}/unlike', [LikeController::class, 'unlike']);
    Route::get('/posts/{id}/likes', [LikeController::class, 'postLikes']);
});
```

4) app/Http/Controllers/AuthController.php
- Módosítsd a `login` metódust, hogy JWT tokent adjon vissza (JWTAuth::attempt), és a `logout` metódust, hogy a tokent invalidálja.

Példa (AuthController fontos részei):
```php
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        try {
            $request->validate([
                'name' => 'required|string|max:255',
                'email' => 'required|email|unique:users,email',
                'password' => 'required|string|confirmed|min:8',
                'profile_picture' => 'nullable|string|max:255',
            ]);
        } catch (ValidationException $e) {
            return response()->json([
                'message' => 'Failed to register user',
                'errors' => $e->errors()
            ], 422);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'profile_picture' => $request->profile_picture,
        ]);

        return response()->json([
            'message' => 'User created successfully',
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'profile_picture' => $user->profile_picture,
            ],
        ], 201);
    }

    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        try {
            if (! $token = JWTAuth::attempt($credentials)) {
                return response()->json(['message' => 'Invalid email or password'], 401);
            }
        } catch (JWTException $e) {
            return response()->json(['message' => 'Could not create token'], 500);
        }

        $user = auth()->user();

        return response()->json([
            'message' => 'Login successful',
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'profile_picture' => $user->profile_picture,
            ],
            'access' => [
                'token' => $token,
                'token_type' => 'Bearer'
            ]
        ]);
    }

    public function logout(Request $request)
    {
        try {
            JWTAuth::parseToken()->invalidate();
        } catch (JWTException $e) {
            return response()->json(['message' => 'Failed to logout, token invalid or missing'], 400);
        }

        return response()->json(['message' => 'Logout successful']);
    }

    public function me(Request $request)
    {
        $user = $request->user();

        return response()->json([
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'profile_picture' => $user->profile_picture,
            ]
        ], 200);
    }
}
```

Tesztek módosítása
- A repository-ban található `tests/Feature/AuthTest.php` és más tesztek `actingAs($user, 'sanctum')`-t használnak. JWT esetén a tesztekben hozd létre a tokent `JWTAuth::fromUser($user)`-ral, és a kéréseknél add meg a `Authorization` fejlécet.

Példa módosítások AuthTest-hez:
```php
use Tymon\JWTAuth\Facades\JWTAuth;

public function test_login_returns_token()
{
    $user = User::create([
        'name' => 'LoginUser',
        'email' => 'login@example.com',
        'password' => Hash::make('Jelszo_2025'),
    ]);

    $response = $this->postJson('/api/login', [
        'email' => 'login@example.com',
        'password' => 'Jelszo_2025',
    ]);

    $response->assertStatus(200)
        ->assertJsonStructure(['message','user','access' => ['token','token_type']]);
}

public function test_me_returns_authenticated_user()
{
    $user = User::create([
        'name' => 'TestUser',
        'email' => 'testuser@example.com',
        'password' => Hash::make('Jelszo_2025'),
    ]);

    $token = JWTAuth::fromUser($user);

    $response = $this->withHeaders([
        'Authorization' => 'Bearer '.$token,
        'Accept' => 'application/json',
    ])->getJson('/api/users/me');

    $response->assertStatus(200)
        ->assertJsonPath('user.email', $user->email);
}
```

Postman / kliens
- Regisztráció: POST /api/register (nem védett)
- Bejelentkezés: POST /api/login (nem védett) — válaszként kapsz egy JWT tokent: `access.token`
- Védett végpontok: minden kérésben add meg:
  `Authorization: Bearer <token>`

Példa login válasz:
```json
{
  "message": "Login successful",
  "user": { "id": 1, "name": "Test", "email": "test@example.com", "profile_picture": null },
  "access": {
    "token": "eyJ0eXAiOiJKV1QiLCJh...",
    "token_type": "Bearer"
  }
}
```

Hibakezelés
- Érvénytelen vagy hiányzó token esetén a JWT middleware 401 státuszt ad vissza. Ajánlott egységes üzenetet használni:
```json
{
  "message": "Invalid token"
}
```
- Validációs hibák: 422
- Jogosultság hiánya: 403

Ellenőrzés / manuális tesztelés
1. Futtasd a telepítést és generáld a secret-et (lásd fent).
2. Indítsd a szervert: `php artisan serve`
3. Regisztrálj egy usert: POST /api/register
4. Jelentkezz be: POST /api/login → kapott tokennel próbáld meg a GET /api/users/me-t
5. Próbáld meg a /api/logout-ot a tokennel — azután a tokennel való hozzáférésnek 401-et kell adnia.




