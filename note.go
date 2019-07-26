package ssloff

// connect: cid dst
// tlsstart: cid dst
// up: cid data
// upeof: cid
// upclose: cid

// down: cid data
// downeof: cid
// downclose: cid

/*

client_reader:
	io_input:
		kClientInputConnect
			->remote_writer
		kClientInputUp
			->remote_writer
		kClientInputUpEOF
			->remote_writer
	io_error:
		kClientClose->remote_writer
		kClientClose->client_writer
		exit
	event_input:
		kClientClose
			exit

client_writer:
	event_input:
		kRemoteInputDown
		kRemoteInputDownEOF
		kClientClose
			exit
	io_error:
		kClientClose->client_reader
		kClientClose->remote_writer
		exit

remote_connector:
	remote_closed:
		kClientClose->client_reader
		kClientClose->client_writer

remote_reader:
	io_input:
		kRemoteInputDown
			->client_writer
		kRemoteInputDownEOF
			->client_writer
		kClientClose
			kClientClose->client_reader
			kClientClose->client_writer
	event_input:
		kRemoteClose
			exit
	io_error:
		kRemoteClose->remote_writer
		exit

remote_writer:
	event_input:
		kClientClose
		kClientInputConnect
		kClientInputUp
		kClientInputUpEOF
		kRemoteClose
			exit
	io_error:
		kRemoteClose->remote_reader
		exit

*/

/*

local_acceptor:
	local_closed:
		kClientClose -> target_reader
		kClientClose -> target_writer

local_reader:
	io_input:
		kClientInputConnect
			-> target_writer
		kClientInputUp
			-> target_writer
		kClientInputUpEOF
			-> target_writer
		kClientClose
			kClientClose -> target_reader
			kClientClose -> target_writer
	event_input:
		kLocalClose
			exit
	io_error:
		kLocalClose -> local_writer
		exit

local_writer:
	event_input:
		kRemoteInputDown
		kRemoteInputDownEOF
		kClientClose
		kLocalClose
			exit
	io_error:
		kLocalClose -> local_reader
		exit

target_connector:
	io_error:
		kClientClose -> local_writer

target_reader:
	io_input:
		kRemoteInputDown
			-> local_writer
		kRemoteInputDownEOF
			-> local_writer
			exit
	io_error:
		kClientClose -> local_writer
		kClientClose -> target_writer
		exit
	event_input:
		kClientClose
			exit

target_writer:
	event_input:
		kClientInputUp
		kClientInputUpEOF
		kClientClose
			exit
	io_error:
		kClientClose -> target_reader
		kClientClose -> local_writer
		exit

*/
