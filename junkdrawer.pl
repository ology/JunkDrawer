#!/usr/bin/env perl
use Mojolicious::Lite -signatures;
 
use Crypt::Passphrase ();
use Crypt::Passphrase::Argon2 ();
use Mojo::SQLite ();
use Path::Tiny qw(path);

use constant BACKUP   => 'JunkDrawer'; # named symlink to the backup
use constant FILESIZE => 4_000_000;    # maximum allowed upload bytes

plugin 'RenderFile';

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
        return $c->render_file(filepath => $subdir->absolute);
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
    my $file = $c->req->upload('file');
    if ($file->size > FILESIZE) {
        $c->flash(error => 'File size too big');
        return $c->redirect_to($url);
    }
    my $destination = $subdir->child($file->filename);
    $file->move_to($destination);
    unless ($destination->exists) {
        $c->flash(error => 'Something went wrong');
        return $c->redirect_to($url);
    }
  }
  return $c->redirect_to($url);
} => 'upload';

post '/new_folder' => sub ($c) {
  my $location = $c->param('location') || '';
  my $folder = $c->param('folder') || '';
  my $url = $c->url_for('files')->query(location => $location);
  my $root = path('.');
  my $subdir = $root->child($location);
  if ($subdir->exists && $subdir->is_dir) {
    my $destination = $subdir->child($folder);
    $destination->mkdir || die $!;
    unless ($destination->exists) {
        $c->flash(error => 'Something went wrong');
        return $c->redirect_to($url);
    }
  }
  return $c->redirect_to($url);
} => 'new_folder';

sub _dir_iter {
  my ($c, $where, $children) = @_;
  my $user = $c->session->{user};
  my $iter = $where->iterator({ follow_symlinks => 1 });
  while (my $path = $iter->()) {
    my $backup = path(BACKUP, $user);
    (my $name = $path) =~ s/$backup\///;
    my @stat = stat $path;
    push @$children, {
      is_dir => $path->is_dir ? 1 : 0,
      name   => $name,
      path   => $path,
      size   => $stat[7],
      time   => $stat[9],
    } unless $path->basename =~ /^\./;
  }
stat
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
% title 'Backup';
<div class="modal fade" id="saveModal" tabindex="-1" aria-labelledby="saveModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title">Save as...</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <p>Save this file to your local drive?</p>
        <code class="source"></code>
      </div>
      <div class="modal-footer">
        <form method="get">
          <input type="hidden" class="location" name="location" value="">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
          <button type="submit" class="btn btn-primary">Save</button>
        </form>
      </div>
    </div>
  </div>
</div>
% unless ($content) {
<form action="<%= url_for('new_folder') %>" method="post">
  <input type="hidden" name="location" value="<%= $location %>">
  <label for="folder"><b>New folder</b>:</label>
  <input type="text" id="folder" name="folder" class="form-control">
  <button type="submit" class="btn btn-sm btn-primary">Submit</button>
</form>
<p></p>
<form method="post" enctype="multipart/form-data">
  <input type="hidden" name="location" value="<%= $location %>">
  <label for="file"><b>Upload file</b>:</label>
  <input type="file" id="file" name="file" class="form-control">
  <button type="submit" class="btn btn-sm btn-primary">Submit</button>
</form>
% }
<hr>
% if ($content) {
<p><%= $content %></p>
% } else {
<p>Items under <code><%= $place %>/</code>:</p>
<table class="table">
  <thead>
    <tr>
      <th scope="col">Folder or file</th>
      <th scope="col">Size</th>
      <th scope="col">Date</th>
    </tr>
  </thead>
  <tbody>
%   for my $child (@$children) {
    <tr class="<%= $child->{is_dir} ? '' : 'table-success' %>">
      <td><button type="button" class="btn btn-clear item" data-source="<%= $child->{path} %>" data-bs-toggle="modal" data-bs-target="#saveModal"><%= $child->{name} %></a></td>
      <td><%= $child->{size} %> bytes</td>
      <td><%= scalar localtime $child->{time} %></td>
    </tr>
%   }
  </tbody>
</table>
% }
<script>
$(document).ready(function() {
  $('.item').click(function() {
    $('.source').text(this.dataset.source);
    $('.location').val(this.dataset.source);
  });
});
</script>

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
