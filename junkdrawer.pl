#!/usr/bin/env perl
use Mojolicious::Lite -signatures;
 
use Crypt::Passphrase ();
use Crypt::Passphrase::Argon2 ();
use Mojo::SQLite ();
use Path::Tiny qw(path);

use constant BACKUP   => 'JunkDrawer'; # named symlink to the backup
use constant FILESIZE => 4_000_000;    # maximum allowed upload bytes

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
  my $user = $c->session->{user};
  my $children = [];
  my $content = '';
  my $root = path('.');
  if ($location) {
    my $subdir = $root->child($location);
    if ($subdir->exists) {
      if ($subdir->is_dir) {
        _dir_iter($c, $subdir, $children);
      }
      else {
        $content = "Is a file! $subdir";
      }
    }
    else {
      $content = "No such file or directory: $subdir";
    }
  }
  else {
    $location = $root->child(BACKUP, $user);
    _dir_iter($c, $location, $children);
  }
  my $backup = path(BACKUP);
  (my $place = $location) =~ s/$backup\///;
  $c->render(
    template => 'files',
    place    => $place,
    location => $location,
    children => $children,
    content  => $content,
  );
} => 'files';

post '/files' => sub ($c) {
  my $location = $c->param('location') || '';
  my $url = $c->url_for('files')->query(location => $location);
  my $root = path('.');
  my $subdir = $root->child($location);
  if ($subdir->exists && $subdir->is_dir) {
    # $subdir->child('blah')->mkdir || die $!;
    my $file = $c->req->upload('files');
    if ($file->size > FILESIZE) {
        $c->flash(error => 'File size too big');
        return $c->redirect_to($url);
    }
    my $destination = $subdir->child($file->filename);
    $file->move_to($destination);
    unless (-e $destination) {
        $c->flash(error => 'Something went wrong');
        return $c->redirect_to($url);
    }
  }
  return $c->redirect_to($url);
} => 'upload';

sub _dir_iter {
  my ($c, $where, $children) = @_;
  my $user = $c->session->{user};
  my $iter = $where->iterator({ follow_symlinks => 1 });
  while (my $path = $iter->()) {
      my $backup = path(BACKUP, $user);
      (my $name = $path) =~ s/$backup\///;
      push @$children, { name => $name, path => $path, size => -s $path };
  }
  return $children;
}

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
% layout 'default';
% title 'Junk::Drawer';
<p>Upload, search, view, etc. forms</p>
<form method="post">
  <input type="hidden" name="location" value="<%= $location %>">
  <button type="submit">Submit</button>
</form>
<hr>
% if ($content) {
<p><%= $content %></p>
% } else {
<p>Items under <code><%= $place %>/</code>:</p>
<ul>
%   for my $child (@$children) {
  <li><a href="<%= url_for('files')->query(location => $child->{path}) %>"><%= $child->{name} %></a> <%= $child->{size} %> bytes</li>
%   }
</ul>
% }

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
