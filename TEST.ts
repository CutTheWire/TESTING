import { Request, Response, NextFunction } from "express"
import { BadRequestException, ConflictException } from "../utils/Exception"
import validator from "../utils/validator";
import { emailRegExp, idRegExp, onlyNumberRegExp, pwRegExp } from "../utils/regExp";
import ResponseResult from "../utils/ResponseResult";
import redisClient from "../utils/redisClient";
import prisma from "../utils/prisma";
import { hash } from "../utils/hash";
import { createToken, verifySocialLoginToken } from "../utils/token";
import { add1Month } from "../utils/time";
import { sendPushNoti } from "../utils/send";

// 회원가입 하기
export const signup = async (req: Request, res: Response, next: NextFunction) => {
    //from FE
    const inputId = req.body.id;
    const inputPw = req.body.pw;
    const inputEmail = req.body.email;
    const phoneNumber = req.body.phoneNumber;
    const inputName = req.body.name;
    const inputGender = Number(req.body.gender);
    const autoLogin = req.body.autoLogin || false;
    const deviceToken = req.body.deviceToken || null;

    //to FE
    const result = new ResponseResult();

    //validation check
    if (!validator(inputId).isString().testRegExp(idRegExp).end())
        return next(new BadRequestException('아이디 형식이 올바르지 않습니다.'));
    if (!validator(inputPw).isString().testRegExp(pwRegExp).end())
        return next(new BadRequestException('비밀번호 형식이 올바르지 않습니다.'));
    if (inputEmail && !validator(inputEmail).isString().testRegExp(emailRegExp).end())
        return next(new BadRequestException('이메일 형식이 올바르지 않습니다'));
    if (!validator(phoneNumber).isString().length(10, 11).testRegExp(onlyNumberRegExp).end())
        return next(new BadRequestException('핸드폰 번호 형식이 올바르지 않습니다.'));
    if (!validator(inputName).isString().length(2, 10).end())
        return next(new BadRequestException('이름/닉네임 형식이 올바르지 않습니다.'));
    if (inputGender && !validator(inputGender).isNumber().includes([1, 2]).end())
        return next(new BadRequestException('성별 형식이 올바르지 않습니다.'));
    if (typeof autoLogin !== 'boolean')
        return next(new BadRequestException('autoLogin 형식이 올바르지 않습니다.'));


    //main
    try {
        const certifiedState = await redisClient.exists(`certified-number-${phoneNumber}`);

        if (!certifiedState) {
            return next(new BadRequestException('휴대폰 인증이 되어있지 않습니다. 휴대폰 인증을 먼저 해주세요.'));
        }

        const user = await prisma.user.findFirst({
            where: {
                phoneNumber: phoneNumber
            },
            select: {
                userIdx: true,
                provider: true,
                email: true
            }
        });

        if (user) {
            const message =
                user.provider === 'local' ?
                    '같은 핸드폰 번호로 가입된 계정이 있습니다.' :
                    `${user.provider}로그인으로 가입된 번호입니다.`;
            return next(new BadRequestException(message));
        }

        const userId = await prisma.user.findFirst({
            where: {
                id: inputId,
                deletedAt: null
            },
            select: {
                userIdx: true
            }
        });

        if (userId)
            return next(new BadRequestException('이미 존재하는 아이디입니다.'));

        const signupUser = await prisma.user.create({
            data: {
                id: inputId,
                pw: hash(inputPw),
                email: inputEmail,
                name: inputName,
                phoneNumber: phoneNumber,
                gender: inputGender,
                deviceToken
            },
            select: {
                userIdx: true
            }
        });

        await redisClient.del(`certified-number-${phoneNumber}`);

        result.data.token = createToken({
            userIdx: signupUser.userIdx
        }, autoLogin ? '14d' : undefined);
    } catch (err) {
        return next(new ConflictException('예상하지 못한 에러가 발생했습니다.', err));
    }

    //send result
    res.status(result.status).send(result);
}

// 소셜 로그인 회원가입 하기
export const socialLoginSignup = async (req: Request, res: Response, next: NextFunction) => {
    //from FE
    const inputEmail = req.body.email;
    const phoneNumber = req.body.phoneNumber;
    const inputName = req.body.name;
    const inputGender = Number(req.body.gender || 0);
    const provider: 'naver' | 'kakao' = req.body.provider;
    const accessToken = req.body.accessToken;
    const deviceToken = req.body.deviceToken || null;
    const autoLogin = req.body.autoLogin || false;

    //to FE
    const result = new ResponseResult();

    //validation check
    if (inputEmail && !validator(inputEmail).isString().testRegExp(emailRegExp).end())
        return next(new BadRequestException('이메일 형식이 올바르지 않습니다'));
    if (!validator(phoneNumber).isString().length(10, 11).testRegExp(onlyNumberRegExp).end())
        return next(new BadRequestException('핸드폰 번호 형식이 올바르지 않습니다.'));
    if (!validator(inputName).isString().length(2, 10).end())
        return next(new BadRequestException('이름/닉네임 형식이 올바르지 않습니다.'));
    if (req.body.gender && !validator(inputGender).isNumber().includes([0, 1, 2]).end())
        return next(new BadRequestException('성별 형식이 올바르지 않습니다.'));
    if (!validator(provider).isString().includes(['naver', 'kakao']).end())
        return next(new BadRequestException('provider는 naver또는 kakao이어야 합니다.'));
    if (!accessToken)
        return next(new BadRequestException('accessToken이 존재하지 않습니다.'));
    if (typeof autoLogin !== 'boolean')
        return next(new BadRequestException('autoLogin타입이 유효하지 않습니다.'));

    try {
        const snsId = await verifySocialLoginToken(accessToken, provider);

        if (!snsId)
            return next(new BadRequestException('Access Token이 만료되었습니다. 다시 시도해주세요.'));

        const certifiedState = await redisClient.exists(`certified-number-${phoneNumber}`);

        if (!certifiedState) {
            return next(new BadRequestException('휴대폰 인증이 되어있지 않습니다. 휴대폰 인증을 먼저 해주세요.'));
        }

        const user = await prisma.user.findFirst({
            where: {
                OR: [
                    {
                        phoneNumber
                    },
                    {
                        snsId
                    }
                ]
            },
            select: {
                userIdx: true,
                provider: true,
                email: true,
                snsId: true,
                phoneNumber: true
            }
        });

        if (user && user?.phoneNumber === phoneNumber)
            return next(new BadRequestException(user.provider === 'local' ? '같은 핸드폰 번호로 가입된 계정이 있습니다.' : `${user.provider}로그인으로 가입된 번호입니다.`));

        if (user && user?.snsId === snsId)
            return next(new BadRequestException('이미 가입된 계정입니다.'));

        const createUser = await prisma.user.create({
            data: {
                email: inputEmail,
                name: inputName,
                phoneNumber: phoneNumber,
                gender: inputGender,
                snsId: snsId,
                provider: provider,
                deviceToken: deviceToken
            }
        });

        await redisClient.del(`certified-number-${phoneNumber}`);

        result.data.token = createToken({ userIdx: createUser.userIdx }, autoLogin ? '14d' : undefined);
    } catch (err: any) {
        return next(new ConflictException('예상하지 못한 에러가 발생했습니다.', err));
    }

    res.status(result.status).send(result);
}

// iot 고유번호 등록하기
export const addIot = async (req: Request, res: Response, next: NextFunction) => {
    //from FE
    const iotId = req.body.iot;
    const loginUserIdx = req.userIdx;
    const name = req.body.name || null;

    //to FE
    const result = new ResponseResult();

    if (!iotId)
        return next(new BadRequestException('iot 고유번호가 유효하지 않습니다.'));
    if (!validator(name).isString().length(2, 10).end())
        return next(new BadRequestException('name이 유효하지 않습니다.'));

    try {
        await prisma.iot.upsert({
            where: {
                iotId
            },
            update: {
                userIdx: loginUserIdx,
                iotName: name
            },
            create: {
                iotId,
                userIdx: loginUserIdx,
                iotName: name
            }
        });
    } catch (err) {
        return next(new ConflictException('예상하지 못한 에러가 발생했습니다.', err));
    }

    res.status(result.status).send(result);
}

// iot 정보 가져오기
export const getIotInfo = async (req: Request, res: Response, next: NextFunction) => {
    //to FE
    const result = new ResponseResult();

    try {
        result.data.collectionDate = new Date('2023-08-26');
        result.data.name = '푸드집02';
        result.data.restFilterAmount = 78;
    } catch (err) {
        return next(new ConflictException('예상하지 못한 에러가 발생했습니다.', err));
    }

    res.status(result.status).send(result);
}

// 사용자 구독 정보 가져오기
export const getSubscribeState = async (req: Request, res: Response, next: NextFunction) => {
    //from FE
    const loginUserIdx = req.userIdx;

    //to FE
    const result = new ResponseResult();

    try {
        const subscribe = await prisma.userSubscribe.findFirst({
            where: {
                userIdx: loginUserIdx,
                createdAt: {
                    lte: new Date()
                },
                expiredAt: {
                    gte: new Date()
                }
            },
            select: {
                subscribeIdx: true,
                expiredAt: true,
                createdAt: true
            }
        });

        result.data.subscribeState = subscribe !== null;

        if (subscribe) {
            result.data.startDate = subscribe.createdAt;
            result.data.endDate = subscribe.expiredAt;
            result.data.collectionDate = new Date('2023-08-26');
            result.data.filterChangeDate = new Date('2023-09-26');
        }
    } catch (err) {
        return next(new ConflictException('예상하지 못한 에러가 발생했습니다.', err));
    }

    res.status(result.status).send(result);
}

// 구독 하기
export const subscribe = async (req: Request, res: Response, next: NextFunction) => {
    //from FE
    const loginUserIdx = req.userIdx;

    //to FE
    const result = new ResponseResult();

    try {
        const subscribe = await prisma.userSubscribe.findFirst({
            where: {
                userIdx: loginUserIdx,
                createdAt: {
                    lte: new Date()
                },
                expiredAt: {
                    gte: new Date()
                }
            },
            select: {
                subscribeIdx: true,
                expiredAt: true
            }
        });

        if (subscribe) {
            await prisma.userSubscribe.update({
                where: {
                    subscribeIdx: subscribe.subscribeIdx
                },
                data: {
                    expiredAt: add1Month(subscribe.expiredAt)
                }
            });
        } else if (!subscribe) {
            await prisma.userSubscribe.create({
                data: {
                    userIdx: loginUserIdx
                }
            });
        }
    } catch (err) {
        return next(new ConflictException('예상하지 못한 에러가 발생했습니다.', err));
    }

    res.status(result.status).send(result);
}

// 푸시 알림 보내기
export const sendPushNotification = async (req: Request, res: Response, next: NextFunction) => {
    const loginUserIdx = req.userIdx;
    const inputTitle = req.query.title?.toString() || 'test';
    const contents = req.query.contents?.toString() || 'test contents';

    const result = new ResponseResult();

    try {
        const user = await prisma.user.findFirst({
            where: {
                userIdx: loginUserIdx,
                deletedAt: null
            },
            select: {
                userIdx: true,
                deviceToken: true
            }
        });

        if (!user?.deviceToken)
            return next(new BadRequestException('디바이스 토큰이 존재하지 않습니다.'));

        await sendPushNoti(user.deviceToken, inputTitle, contents);
    } catch (err) {
        return next(new ConflictException('예상하지 못한 에러가 발생했습니다.', err));
    }

    res.status(result.status).send(result);
}
