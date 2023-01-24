#!/usr/bin/env perl
use strict;
use warnings;
 
use HTTP::Server::Brick ();

my $s = HTTP::Server::Brick->new(port => 8080);
$s->mount('/' => { path => 'public/tmp' });
$s->start;
