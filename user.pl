#!/usr/bin/env perl
use strict;
use warnings;

use Crypt::Passphrase ();
use Crypt::Passphrase::Argon2 ();
use Mojo::SQLite ();
use Term::ReadKey qw(ReadMode ReadLine);

my ($user, $email, $pass) = @ARGV;

die "Usage: perl $0 username email [password]\n" unless $user;

add($user, $email, $pass);

sub add {
  my $sql = Mojo::SQLite->new('sqlite:auth.db');
  my $record = $sql->db->query('select id from account where name = ?', $user)->hash;
  my $id = $record ? $record->{id} : undef;
  if ($id) {
    warn "User '$user' is already known.\n";
  }
  else {
    unless ($pass) {
      ReadMode('noecho');
      print "Password for user '$user': ";
      $pass = ReadLine(0);
      chomp $pass;
      print "\n";
      ReadMode('restore');
    }
    my $authenticator = Crypt::Passphrase->new(encoder => 'Argon2');
    my $new_hash = $authenticator->hash_password($pass);
    $sql->db->query('insert into account (name, email, password) values (?, ?, ?)', $user, $email, $new_hash);
    print "User: $user, email: $email successfully inserted.\n";
  }
};
