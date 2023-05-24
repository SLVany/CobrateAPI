using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Text;


var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication(o =>
{
    o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    o.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(o =>
{
    o.TokenValidationParameters = new TokenValidationParameters
    {
        IssuerSigningKey = new SymmetricSecurityKey
            (Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true
    };
});

builder.Services.AddAuthorization();

builder.Services.AddDbContext<CobrateContext>(options =>
    options.UseMySQL(builder.Configuration["ConnectionStrings:MySql"]));

var securityScheme = new OpenApiSecurityScheme()
{
    Name = "Authorization",
    Type = SecuritySchemeType.ApiKey,
    Scheme = "Bearer",
    BearerFormat = "JWT",
    In = ParameterLocation.Header,
    Description = "JSON Web Token based security",
};

var securityReq = new OpenApiSecurityRequirement()
{
    {
        new OpenApiSecurityScheme
        {
            Reference = new OpenApiReference
            {
                Type = ReferenceType.SecurityScheme,
                Id = "Bearer"
            }
        },
        new string[] {}
    }
};
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "Cobrate API", Version = "v1" });
    c.AddSecurityDefinition("Bearer", securityScheme);
    c.AddSecurityRequirement(securityReq);
});

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", [AllowAnonymous] () => "Cobrate API");

app.MapPost("/login", [AllowAnonymous] async (User user, CobrateContext db) =>
{
    var userdb = await db.Users.FindAsync(user.Username);
    if (userdb is null) return Results.NotFound(user.Username);
    if (userdb.Password != user.Password) return Results.Unauthorized();
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]));
    var jwtTokenHandler = new JwtSecurityTokenHandler();
    var descriptor = new SecurityTokenDescriptor()
    {
        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256),
        Expires = DateTime.UtcNow.AddHours(1)
    };
    var token = jwtTokenHandler.CreateToken(descriptor);
    var jwtToken = jwtTokenHandler.WriteToken(token);

    var jwt = "{ \"jwt\": \"" + jwtToken + "\"}";
    return Results.Text(jwt);
});
/*******CRUD MOVIMIENTOS*********/
app.MapGet("/movimientos", [Authorize] async (CobrateContext db) =>
{
    return await db.Movimientos.ToListAsync();
});

app.MapGet("/movimientos/{id}", [Authorize] async (int id, CobrateContext db) =>
{
    var movimiento = await db.Movimientos.FindAsync(id);
    if (movimiento is null)
    {
        return Results.NotFound();
    }
    return Results.Ok(movimiento);
});

app.MapPost("/movimientos", [Authorize] async (Movimiento m, CobrateContext db) =>
{
    m.Fecha = DateTime.Now;
    db.Movimientos.Add(m);
    await db.SaveChangesAsync();
    return Results.Created($"/movimientos/{m.Id}", m);
});

app.MapPut("/movimientos/{id}", [Authorize] async (int id, Movimiento m, CobrateContext db) =>
{
    var movimiento = await db.Movimientos.FindAsync(id);
    if (movimiento is null)
    {
        return Results.NotFound();
    }
    movimiento.Id = m.Id;
    movimiento.Tagid = m.Tagid;
    movimiento.Cargo = m.Cargo;
    movimiento.Abono = m.Abono;
    movimiento.Fecha = m.Fecha;
    await db.SaveChangesAsync();
    return Results.Ok(movimiento);
});

app.MapDelete("/movimientos/{id}", [Authorize] async (int id, CobrateContext db) =>
{
    var movimiento = await db.Movimientos.FindAsync(id);
    if (movimiento is null)
    {
        return Results.NotFound();
    }
    db.Movimientos.Remove(movimiento);
    await db.SaveChangesAsync();
    return Results.Ok(movimiento);
});

/*******CRUD COSTOS*********/
app.MapGet("/costos", [Authorize] async (CobrateContext db) =>
{
    return await db.Costos.ToListAsync();
});

app.MapGet("/costos/{id}", [Authorize] async (int id, CobrateContext db) =>
{
    var costo = await db.Costos.FindAsync(id);
    if (costo is null)
    {
        return Results.NotFound();
    }
    return Results.Ok(costo);
});

app.MapPost("/costos", [Authorize] async (Costo c, CobrateContext db) =>
{
    db.Costos.Add(c);
    await db.SaveChangesAsync();
    return Results.Created($"/costos/{c.Id}", c);
});

app.MapPut("/costos/{id}", [Authorize] async (int id, Costo c, CobrateContext db) =>
{
    var costo = await db.Costos.FindAsync(id);
    if (costo is null)
    {
        return Results.NotFound();
    }
    costo.Id = c.Id;
    costo.Tarifa = c.Tarifa;
    costo.Descripcion = c.Descripcion;
    await db.SaveChangesAsync();
    return Results.Ok(costo);
});

app.MapDelete("/costos/{id}", [Authorize] async (int id, CobrateContext db) =>
{
    var costo = await db.Costos.FindAsync(id);
    if (costo is null)
    {
        return Results.NotFound();
    }
    db.Costos.Remove(costo);
    await db.SaveChangesAsync();
    return Results.Ok(costo);
});

/*******CRUD SALDOS*********/
app.MapGet("/saldos", [Authorize] async (CobrateContext db) =>
{
    return await db.Saldos.ToListAsync();
});

app.MapGet("/saldos/{id}", [Authorize] async (int id, CobrateContext db) =>
{
    var saldo = await db.Saldos.FindAsync(id);
    if (saldo is null)
    {
        return Results.NotFound();
    }
    return Results.Ok(saldo);
});

app.MapPost("/saldos", [Authorize] async (Saldo s, CobrateContext db) =>
{
    db.Saldos.Add(s);
    await db.SaveChangesAsync();
    return Results.Created($"/saldos/{s.Id}", s);
});

app.MapPut("/saldos/{id}", [Authorize] async (int id, Saldo s, CobrateContext db) =>
{
    var saldo = await db.Saldos.FindAsync(id);
    if (saldo is null)
    {
        return Results.NotFound();
    }
    saldo.Id = s.Id;
    saldo.Tagid = s.Tagid;
    saldo.SaldoTotal = s.SaldoTotal;
    await db.SaveChangesAsync();
    return Results.Ok(saldo);
});

app.MapDelete("/saldos/{id}", [Authorize] async (int id, CobrateContext db) =>
{
    var saldo = await db.Saldos.FindAsync(id);
    if (saldo is null)
    {
        return Results.NotFound();
    }
    db.Saldos.Remove(saldo);
    await db.SaveChangesAsync();
    return Results.Ok(saldo);
});

app.Run();


class User
{
    [Key]
    public string? Username { get; set; }
    public string? Password { get; set; }
}
class Saldo
{
    [Key]
    public int Id { get; set; }
    public int Tagid { get; set; }
    public double SaldoTotal { get; set; }
}

class Movimiento
{
    [Key]
    public int Id { get; set; }
    public int Tagid { get; set; }
    public double Cargo { get; set; }
    public double Abono { get; set; }
    public DateTime Fecha { get; set; }
}

class Costo
{
    [Key]
    public int Id { get; set; }
    public int Tarifa { get; set; }
    public string? Descripcion { get; set; }
}

class CobrateContext : DbContext
{
    public DbSet<User> Users => Set<User>();
    public DbSet<Saldo> Saldos => Set<Saldo>();
    public DbSet<Movimiento> Movimientos => Set<Movimiento>();
    public DbSet<Costo> Costos => Set<Costo>();
    public CobrateContext(DbContextOptions<CobrateContext> options) : base(options)
    {
    }
}
