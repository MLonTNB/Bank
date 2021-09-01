import json

from rest_framework import serializers
from v1.accounts.models.account import Account
from v1.bank_transactions.models.bank_transaction import BankTransaction
from v1.blocks.models.block import Block
from v1.confirmation_blocks.models.confirmation_block import ConfirmationBlock
from v1.keys.models.key import Key
from v1.self_configurations.helpers.self_configuration import get_self_configuration
from v1.self_configurations.helpers.signing_key import get_signing_key
from v1.utils.encryption import symmetric_encrypt, asymmetric_encrypt, asymmetric_decrypt


def get_json_transactions(encryption_key):
    return []


def create_bank_transactions(*, block, message):
    """Crete bank transactions from given block data"""
    bank_transactions = []

    sender = block.get('sender')

    encrypted_symmetric_key = None
    keys_to_add = []
    keys_to_delete = []
    for tx in message['txs']:
        json_data_for_db = None
        if 'json_data' in tx:
            json_data = tx.get('json_data')
            type = json_data.get('type')
            encryption_key = json_data.get('account', sender)

            if type not in ["register_data", "append_data", "ask_for_access", "grant_access", "revoke_access"]:
                continue

            node_private_key = get_signing_key()
            node_public_key = node_private_key.verify_key
            if type == "register_data" or type == "grant_access":
                keys_to_add.append({'accessor': encryption_key, 'patient_id': sender})
                # add the node as an accessor so it can manipulate the symmetric key
                keys_to_add.append({'accessor': node_public_key, 'patient_id': sender})
            elif type == "revoke_access":
                keys_to_delete.append({'accessor': encryption_key, 'patient_id': sender})
                # get all transactions that contain JSON data for the patient
                transactions = get_json_transactions(sender)
                new_transaction_data = {}
                for transaction in transactions:
                    if transaction["json_data"]["type"] in ["register_data", "append_data"]:
                        decrypted_data = asymmetric_decrypt(transaction["json_data"]["data"], node_private_key)
                        new_transaction_data.update(decrypted_data)
                new_data_symmetric_result = symmetric_encrypt(json.dumps(new_transaction_data))

                new_transaction_json_data_for_db = {
                    "patient_id": encryption_key,
                    "type": type
                    "data": new_data_symmetric_result,
                    "access": encrypted_symmetric_key
                }

                new_data_transaction = BankTransaction(
                    amount=0,
                    block=block,
                    fee=tx.get('fee', ''),
                    memo=tx.get('memo', ''),
                    json_data=new_transaction_json_data_for_db,
                    recipient=tx['recipient']
                )
                bank_transactions.append(new_data_transaction)

            symmetric_result = symmetric_encrypt(json.dumps(json_data["data"]))
            encrypted_symmetric_key = asymmetric_encrypt(symmetric_result['key'], encryption_key)

            json_data_for_db = {
                "patient_id": encryption_key,
                "type": type
                "data": symmetric_result['message'],
                "access": encrypted_symmetric_key
            }

        bank_transaction = BankTransaction(
            amount=tx['amount'],
            block=block,
            fee=tx.get('fee', ''),
            memo=tx.get('memo', ''),
            json_data=json_data_for_db,
            recipient=tx['recipient']
        )
        bank_transactions.append(bank_transaction)

    keys_to_add = [Key(
        patient_id=key['patient_id'],
        accessor=key['accessor'],
        encrypted_symmetric_key=encrypted_symmetric_key
    ) for key in keys_to_add]
    Key.objects.bulk_create(keys_to_add)

    keys_to_delete = [Key(
        patient_id=key['patient_id'],
        accessor=key['accessor']
    ) for key in keys_to_delete]
    for key in keys_to_delete:
        key.delete()

    BankTransaction.objects.bulk_create(bank_transactions)


def create_block_and_related_objects(block_data):
    """
    Create block, bank transactions, and account if necessary

    Returns block, block_created
    """
    account_number = block_data['account_number']
    message = block_data['message']
    signature = block_data['signature']
    balance_key = message['balance_key']

    block = Block.objects.filter(balance_key=balance_key).first()

    if block:

        # User is attempting to resend the same exact block
        if block.signature == signature:

            if ConfirmationBlock.objects.filter(block=block).exists():
                raise serializers.ValidationError('Block has already been confirmed')

            return block, False

        # User is using that balance key to send a new block (different Txs)
        BankTransaction.objects.filter(block=block).delete()
        create_bank_transactions(block=block, message=message)

        return block, False

    block = Block.objects.create(
        balance_key=balance_key,
        sender=account_number,
        signature=signature
    )
    create_bank_transactions(block=block, message=message)
    Account.objects.get_or_create(
        account_number=account_number,
        defaults={'trust': 0},
    )

    return block, True
