# SimpleSecurity.DataProtection

> [English](README.md) | 中文

ASP.NET Core `IDataProtectionProvider` 的替代实现。所有密钥都从单个 secret 字符串派生，类似
Laravel (PHP) 的 `APP_KEY`。没有 `~/.aspnet/dataprotection-keys/` 下的密钥环 XML，没有密钥
轮换，也不需要配置共享存储。配置相同 secret 的实例可以互相解密对方的数据。

## 行为

- ASP.NET Core 默认的数据保护会随机生成密钥，写入密钥环（磁盘、Redis 或 Blob 存储），并每 90
  天轮换一次。密钥环丢失后，现有的 cookie、token、防伪令牌都无法解密。
- 本库改用单个固定 secret。secret 由应用提供，库本身不持久化它。没有自动轮换。

## 工作原理

- HKDF-SHA256 为每个 *purpose* 派生独立的 AES-256 密钥。`CreateProtector("cookies")` 和
  `CreateProtector("antiforgery")` 使用不同密钥，因此一个 protector 无法解密另一个 purpose 的
  数据。
- AES-GCM 提供经过认证的加密。其 128 位标签可检测篡改，因此不使用额外的 HMAC。
- 数据格式：`[version:1][nonce:12][tag:16][ciphertext:n]`。版本字节被绑定为 AES-GCM 的关联
  数据。格式可以变更而不破坏旧数据。

## 安装

```bash
dotnet add package SimpleSecurity.DataProtection
```

目标框架：`net8.0`、`net9.0`、`net10.0`。

## 用法

### 内联 secret

```csharp
builder.Services.UseSimpleDataProtection("一个足够长的随机-secret");
```

### 从环境变量读取

```csharp
builder.Services.UseSimpleDataProtection()
    .UseSecretFromEnvironment("APP_KEY");
```

变量不存在或为空时在启动阶段抛出异常。

### 从配置读取（`appsettings.json`、用户机密、Key Vault）

```csharp
builder.Services.UseSimpleDataProtection()
    .UseSecret(builder.Configuration["Security:DataProtectionKey"]!);
```

### options 委托与可选 salt

```csharp
builder.Services.UseSimpleDataProtection(options =>
{
    options.UseSecret(builder.Configuration["Security:Key"]!);
    options.UseSalt("my-app-domain-separator"); // 可选的 HKDF salt
});
```

每个 `UseSimpleDataProtection(...)` 重载都返回 `ISimpleDataProtectionBuilder`，可链式调用：

```csharp
builder.Services
    .UseSimpleDataProtection("secret")
    .UseSalt("tenant-42");
```

### 挂在 host builder 上

`IHostApplicationBuilder` 重载会注册 provider 并返回 builder，适用于 `WebApplicationBuilder`
和 `HostApplicationBuilder`：

```csharp
builder.UseSimpleDataProtection("一个足够长的随机-secret");
// 或
builder.UseSimpleDataProtection(o => o.UseSecret(builder.Configuration["APP_KEY"]!));
```

### 使用 provider

与内置 provider 的 API 相同。注入 `IDataProtectionProvider` 并创建 protector：

```csharp
public class TokenService(IDataProtectionProvider provider)
{
    private readonly IDataProtector _protector = provider.CreateProtector("MyApp.Tokens.v1");

    public string Protect(string value) =>
        Convert.ToBase64String(_protector.Protect(Encoding.UTF8.GetBytes(value)));
}
```

## 注意事项

- secret 需保密且保持稳定。任何持有 secret 的人都能读取和伪造数据。更换 secret 会使现有的
  cookie、token、防伪令牌失效。
- 使用高熵 secret。HKDF 只拉伸输入，不增加熵。请使用 32 字节以上的随机值（例如
  `openssl rand -base64 32`），不要用短口令。
- 相同的 secret 和 salt 产生可互换的实例。secret 必须分发到所有需要互通的实例。
- 没有自动轮换。要轮换，更换 secret（现有数据将无法解密），或升级 purpose 字符串（例如
  `...Tokens.v2`）。

## 许可证

MIT
