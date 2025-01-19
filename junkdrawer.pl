#!/usr/bin/env perl
use Mojolicious::Lite -signatures;
 
use Crypt::Passphrase ();
use Crypt::Passphrase::Argon2 ();
use Mojo::SQLite ();
use Number::Format ();
use Path::Tiny qw(path);

use constant BACKUP   => 'Backup'; # named symlink to the backup
use constant FILESIZE => 100_000_000;  # maximum allowed upload bytes

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

get '/login' => sub { shift->render } => 'login';

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
  my $sort = $c->param('sort') || 'item';
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
    sort     => $sort,
  );
} => 'files';

post '/files' => sub ($c) {
  my $location = $c->param('location') || '';
  my $url = $c->url_for('files')->query(location => $location);
  my $root = path('.');
  my $subdir = $root->child($location);
  if ($subdir->exists && $subdir->is_dir) {
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
  my $nf = Number::Format->new;
  my $iter = $where->iterator({ follow_symlinks => 1 });
  while (my $path = $iter->()) {
    my $stat = $path->stat;
    push @$children, {
      name   => $path->basename,
      path   => $path,
      size   => $nf->format_bytes($stat->[7]),
      bytes  => $stat->[7],
      time   => $stat->[9],
      is_dir => $path->is_dir ? 1 : 0,
    } unless $path->basename =~ /^\./;
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
  <div class="row">
    <div class="col">
      <input class="form-control" type="text" name="username" placeholder="Username">
    </div>
  </div>
  <div class="row">
    <div class="col">
      <input class="form-control" type="password" name="password" placeholder="Password">
    </div>
  </div>
  <div class="row">
    <div class="col">
      <input class="form-control btn btn-primary" type="submit" name="submit" value="Login">
    </div>
  </div>
</form>

@@ files.html.ep
% layout 'default';
% title 'Backup';
<div class="modal fade" id="saveModal" tabindex="-1" aria-labelledby="saveModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title">Save...</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <p>Save this file to your local drive?</p>
        <code class="source"></code>
      </div>
      <div class="modal-footer">
        <form method="get" class="saveForm">
          <input type="hidden" class="location" name="location" value="">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
          <button type="submit" class="btn btn-primary">Save</button>
        </form>
      </div>
    </div>
  </div>
</div>
% unless ($content) {
<form action="<%= url_for('new_folder') %>" method="post" class="padLR">
  <input type="hidden" name="location" value="<%= $location %>">
  <div class="row">
    <input type="text" name="folder" class="form-control" placeholder="New folder" required>
    <button type="submit" class="btn btn-sm btn-primary">Create</button>
  </div>
</form>
<p></p>
<form method="post" enctype="multipart/form-data" class="padLR">
  <input type="hidden" name="location" value="<%= $location %>">
  <div class="row">
    <input type="file" id="file" name="file" class="form-control" required>
    <button type="submit" class="btn btn-sm btn-primary">Upload</button>
  </div>
</form>
% }
<p></p>
<hr>
% if ($content) {
<p><%= $content %></p>
% } else {
<p>Items under <code><%= $place %>/</code>:</p>
<table class="table">
  <thead>
    <tr>
      <th scope="col"><a href="<%= url_for('files')->query(location => $location, sort => 'item') %>" class="nounder padLR">Item</a></th>
      <th scope="col"><a href="<%= url_for('files')->query(location => $location, sort => 'size') %>" class="nounder">Size</a></th>
      <th scope="col"><a href="<%= url_for('files')->query(location => $location, sort => 'date') %>" class="nounder">Date</a></th>
    </tr>
  </thead>
  <tbody>
%   my @sorted;
%   if ($sort eq 'item') {
%     @sorted = sort { fc($a->{name}) cmp fc($b->{name}) } @$children;
%   }
%   elsif ($sort eq 'size') {
%     @sorted = sort { $a->{bytes} <=> $b->{bytes} || fc($a->{name}) cmp fc($b->{name}) } @$children;
%   }
%   elsif ($sort eq 'date') {
%     @sorted = sort { $a->{time} <=> $b->{time} || fc($a->{name}) cmp fc($b->{name}) } @$children;
%   }
%   for my $child (@sorted) {
    <tr>
%     if ($child->{is_dir}) {
      <td><a class="btn btn-clear" href="<%= url_for('files')->query(location => $child->{path}) %>"><%= $child->{name} %>/</a></td>
      <td>&nbsp;</td>
%     } else {
      <td><button type="button" class="btn btn-clear item" data-source="<%= $child->{path} %>" data-bs-toggle="modal" data-bs-target="#saveModal"><%= $child->{name} %></a></td>
      <td><%= $child->{size} %> bytes</td>
%     }
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
  $('.saveForm').on('submit', function(e) {
    $('#saveModal').modal('toggle');
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
      <h2><a href="<%= url_for('files') %>" class="nounder textBlack"><%= title %></a></h2>
<%= content %>
      <p></p>
      <div id="footer" class="text-muted small">
        <hr>
        Built by <a href="http://www.ology.net/">Gene</a>
        with <a href="https://www.perl.org/">Perl</a> and
        <a href="https://mojolicious.org/">Mojolicious</a>
        | <a href="<%= url_for('logout') %>">Logout</a>
      </div>
      <p></p>
    </div>
  </body>
</html>
