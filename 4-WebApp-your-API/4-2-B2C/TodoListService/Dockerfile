#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/core/aspnet:3.1-buster-slim AS base
WORKDIR /app
EXPOSE 44332
EXPOSE 44332

FROM mcr.microsoft.com/dotnet/core/sdk:3.1-buster AS build
WORKDIR /src
COPY ["TodoListService/TodoListService.csproj", "TodoListService/"]
RUN dotnet restore "TodoListService/TodoListService.csproj"
COPY . .
WORKDIR "/src/TodoListService"
RUN dotnet build "TodoListService.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "TodoListService.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "TodoListService.dll"]
