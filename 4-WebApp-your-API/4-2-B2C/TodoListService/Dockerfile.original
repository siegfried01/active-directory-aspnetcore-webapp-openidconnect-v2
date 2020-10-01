FROM mcr.microsoft.com/dotnet/core/aspnet:3.1 AS base
WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/core/sdk:3.1 AS build
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