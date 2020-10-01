FROM mcr.microsoft.com/dotnet/core/aspnet:3.1 AS base
WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/core/sdk:3.1 AS build
WORKDIR /src
COPY ["Client/TodoListClient.csproj", "Client/"]

RUN dotnet restore "Client/TodoListClient.csproj"
COPY . .
WORKDIR "/src/Client"
RUN dotnet build "TodoListClient.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "TodoListClient.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "TodoListClient.dll"]