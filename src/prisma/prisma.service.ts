import { PrismaClient } from '@prisma/client'
import { Injectable } from '@nestjs/common';

@Injectable()
export class PrismaService extends PrismaClient{
    constructor() {
        super({
            datasources: {
                db: {
                    url: process.env.DATABASE_URL,
                },
            },
        });
    }
}
