# Begin commands to execute this file using Docker with bash
# echo docker.exe build . -t siegfried01/todolistclient
# docker.exe build . -t siegfried01/todolistclient
# echo docker.exe push siegfried01/todolistclient
# docker.exe push siegfried01/todolistclient
# End commands to execute this file using Docker with bash
#
# $Log$
#


#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/core/aspnet:3.1-buster-slim AS base
WORKDIR /app
EXPOSE 51803
EXPOSE 44360

FROM mcr.microsoft.com/dotnet/core/sdk:3.1-buster AS build
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
