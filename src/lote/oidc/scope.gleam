import gleam/list
import gleam/result
import gleam/set.{type Set}
import gleam/string

pub type Scope {
  OpenId
  Profile
  OfflineAccess
  PostsRead
  PostsWrite
  PostsDelete
}

pub fn to_string(scope: Scope) -> String {
  case scope {
    OpenId -> "openid"
    Profile -> "profile"
    OfflineAccess -> "offline_access"
    PostsRead -> "posts:read"
    PostsWrite -> "posts:write"
    PostsDelete -> "posts:delete"
  }
}

pub fn from_string(raw: String) -> Result(Scope, String) {
  case raw {
    "openid" -> Ok(OpenId)
    "profile" -> Ok(Profile)
    "offline_access" -> Ok(OfflineAccess)
    "posts:read" -> Ok(PostsRead)
    "posts:write" -> Ok(PostsWrite)
    "posts:delete" -> Ok(PostsDelete)
    _ -> Error(raw)
  }
}

pub fn all() -> List(Scope) {
  [OpenId, Profile, OfflineAccess, PostsRead, PostsWrite, PostsDelete]
}

pub fn bot_assignable() -> List(Scope) {
  [PostsRead, PostsWrite, PostsDelete]
}

pub fn is_bot_assignable(scope: Scope) -> Bool {
  case scope {
    PostsRead | PostsWrite | PostsDelete -> True
    OpenId | Profile | OfflineAccess -> False
  }
}

pub fn parse_space_delimited(raw: String) -> Result(Set(Scope), String) {
  let tokens =
    raw
    |> string.trim
    |> string.split(" ")
    |> list.filter(fn(part) { part != "" })

  use parsed <- result.map(list.try_map(tokens, from_string))
  set.from_list(parsed)
}

pub fn parse_list(raw_scopes: List(String)) -> Result(Set(Scope), String) {
  use parsed <- result.map(list.try_map(raw_scopes, from_string))
  set.from_list(parsed)
}

pub fn to_sorted_strings(scopes: Set(Scope)) -> List(String) {
  all()
  |> list.filter(fn(candidate) { set.contains(scopes, candidate) })
  |> list.map(to_string)
}

pub fn format_space_delimited(scopes: Set(Scope)) -> String {
  scopes
  |> to_sorted_strings
  |> string.join(" ")
}

pub fn is_subset(requested: Set(Scope), allowed: Set(Scope)) -> Bool {
  requested
  |> set.to_list
  |> list.all(fn(s) { set.contains(allowed, s) })
}
