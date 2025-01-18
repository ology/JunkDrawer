#!/usr/bin/env perl
use Mojolicious::Lite -signatures;
 
use Crypt::Passphrase ();
use Crypt::Passphrase::Argon2 ();
use Mojo::SQLite ();

helper auth => sub {
  my $c = shift;
  my $user = $c->param('username');
  my $pass = $c->param('password');
  return 0 unless $user && $pass;
  my $sql = Mojo::SQLite->new('sqlite:auth.db');
  my $record = $sql->db->query('select id, name, password from account where name = ?', $user)->hash;
  my $password = $record ? $record->{password} : undef;
  my $authenticator = Crypt::Passphrase->new(encoder => 'Argon2');
  if (!$authenticator->verify_password($pass, $password)) {
    return 0;
  }
  $c->session(auth => 1);
  $c->session(user => $record->{name});
  $c->session(user_id => $record->{id});
  return 1;
};

get '/' => sub { shift->redirect_to('login') } => 'index';

get '/login' => sub ($c) {
  $c->render(template => 'login');
} => 'login';

post '/login' => sub ($c) {
  if ($c->auth) {
    return $c->redirect_to('files');
  }
  $c->flash('error' => 'Invalid login');
  $c->redirect_to('login');
} => 'auth';

get '/logout' => sub ($c) {
  delete $c->session->{auth};
  delete $c->session->{user};
  delete $c->session->{user_id};
  $c->session(expires => 1);
  $c->redirect_to('login');
} => 'logout';

under sub ($c) {
  return 1 if ($c->session('auth') // '') eq '1';
  $c->redirect_to('login');
  return undef;
};

get '/files' => sub ($c) {
  my $location = $c->param('location') || '';
  if ($location) {
    push $c->static->paths->@*, 'public/tmp';
    $c->static->serve_asset($c->static->paths->@*);
  }
  else {
    $c->render(
      template => 'files',
    );
  }
} => 'files';

app->log->level('info');
app->start;

__DATA__

@@ login.html.ep
% layout 'default';
% title 'Login';
% if (flash('error')) {
  <h2 style="color:red"><%= flash('error') %></h2>
% }
<p></p>
<form action="<%= url_for('auth') %>" method="post">
  <input class="form-control" type="text" name="username" placeholder="Username">
  <br>
  <input class="form-control" type="password" name="password" placeholder="Password">
  <br>
  <input class="form-control btn btn-primary" type="submit" name="submit" value="Login">
</form>

@@ files.html.ep
% title 'Junk::Drawer';
Choose or die!

@@ layouts/default.html.ep
<!DOCTYPE html>
<html lang="en">
  <head>
    <title><%= title %></title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">
    <script src="https://cdn.jsdelivr.net/npm/jquery@3.7.0/dist/jquery.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.min.js" integrity="sha384-cVKIPhGWiC2Al4u+LWgxfKTRIcfu0JTxR+EQDz/bgldoEyl4H0zUF0QKbrJ0EcQF" crossorigin="anonymous"></script>
    <link href="/css/style.css" rel="stylesheet">
  </head>
  <body>
    <div class="container">
      <p></p>
      <h2><%= title %></h2>
<%= content %>
      <p></p>
      <div id="footer" class="text-muted small">
        <hr>
        Built by <a href="http://www.ology.net/">Gene</a>
        with <a href="https://www.perl.org/">Perl</a> and
        <a href="https://mojolicious.org/">Mojolicious</a>
      </div>
      <p></p>
    </div>
  </body>
</html>
