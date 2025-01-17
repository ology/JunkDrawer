#!/usr/bin/env perl
use Mojolicious::Lite -signatures;
 
use Crypt::Passphrase ();
use Crypt::Passphrase::Argon2 ();

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

post '/login' => sub {
  my $c = shift;
  if ($c->auth) {
    return $c->redirect_to('files');
  }
  $c->flash('error' => 'Invalid login');
  $c->redirect_to('login');
} => 'auth';

get '/logout' => sub {
  my $c = shift;
  delete $c->session->{auth};
  delete $c->session->{user};
  delete $c->session->{user_id};
  $c->session(expires => 1);
  $c->redirect_to('login');
} => 'logout';

under sub {
  my $c = shift;
  return 1 if ($c->session('auth') // '') eq '1';
  $c->redirect_to('login');
  return undef;
};

get '/files' => sub ($c) {
  my $action = $c->param('action') || '';  # action to perform
  if ($action eq 'view') {
    $view = 1;
  }
  $c->render(
    template => 'files',
  );
} => 'files';

app->log->level('info');
app->start;
